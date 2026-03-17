#pragma once
// transparency_log.h  -- UML-001 Transparency Log
//
// Design:
//   - Append-only, hash-chained log of all passport lifecycle events.
//   - Each entry commits to the previous entry's hash, forming a tamper-
//     evident chain (analogous to Certificate Transparency logs).
//   - Entries are serialized to a canonical string before hashing so the
//     chain is reproducible across implementations.
//   - The log is write-once: entries cannot be modified or deleted.
//   - Supports three query operations: by sequence number, by passport
//     model_id, and by event type.
//   - In production, back this with a persistent append-only store
//     (e.g., a write-once S3 bucket, Kafka topic, or PostgreSQL
//     append-only table). This in-memory implementation is suitable
//     for testing and single-process deployments.

#include "crypto_utils.h"
#include "key_rotation.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <functional>
#include <optional>

namespace uml001 {

// ---------------------------------------------------------------------------
// TransparencyEntry: one immutable log record
// ---------------------------------------------------------------------------
struct TransparencyEntry {
    uint64_t    sequence_number = 0;    // monotonically increasing, 1-based
    std::string event_type;             // see EVENT_TYPE_* constants below
    std::string actor_id;               // who performed the action
    std::string subject_model_id;       // passport model_id (empty for key events)
    uint32_t    key_id_used     = 0;    // signing key used (0 if not applicable)
    std::string payload_summary;        // human-readable summary (no secrets)
    uint64_t    timestamp       = 0;    // Unix timestamp
    std::string prev_hash;              // SHA-256 of previous entry's canonical form
    std::string entry_hash;             // SHA-256 of this entry's canonical form

    // Event type constants
    static constexpr const char* PASSPORT_ISSUED    = "PASSPORT_ISSUED";
    static constexpr const char* PASSPORT_VERIFIED  = "PASSPORT_VERIFIED";
    static constexpr const char* PASSPORT_REJECTED  = "PASSPORT_REJECTED";
    static constexpr const char* PASSPORT_REVOKED   = "PASSPORT_REVOKED";
    static constexpr const char* PASSPORT_RECOVERED = "PASSPORT_RECOVERED";
    static constexpr const char* KEY_INTRODUCED     = "KEY_INTRODUCED";
    static constexpr const char* KEY_ROTATING       = "KEY_ROTATING";
    static constexpr const char* KEY_RETIRED        = "KEY_RETIRED";
    static constexpr const char* KEY_PURGED         = "KEY_PURGED";
    static constexpr const char* QUORUM_SIGNED      = "QUORUM_SIGNED";  // multi-party
    static constexpr const char* QUORUM_REJECTED    = "QUORUM_REJECTED";

    // Produce a deterministic canonical string for hashing.
    // Fields are serialized in lexicographic key order.
    std::string canonical() const {
        std::ostringstream s;
        s << "actor_id="         << actor_id
          << "&event_type="      << event_type
          << "&key_id_used="     << key_id_used
          << "&payload_summary=" << payload_summary
          << "&prev_hash="       << prev_hash
          << "&sequence_number=" << sequence_number
          << "&subject_model_id="<< subject_model_id
          << "&timestamp="       << timestamp;
        return s.str();
    }
};

// ---------------------------------------------------------------------------
// TransparencyLog: the append-only log
// ---------------------------------------------------------------------------
class TransparencyLog {
public:
    TransparencyLog() {
        // Genesis entry: prev_hash is all-zeros for the first entry
        genesis_hash_ = std::string(64, '0');
    }

    // -----------------------------------------------------------------------
    // append: add a new entry. Returns the sequence number assigned.
    // Throws if the log is in an inconsistent state.
    // -----------------------------------------------------------------------
    uint64_t append(const std::string& event_type,
                    const std::string& actor_id,
                    const std::string& subject_model_id,
                    uint32_t key_id_used,
                    const std::string& payload_summary,
                    uint64_t timestamp) {
        std::lock_guard<std::mutex> lk(mu_);

        TransparencyEntry e;
        e.sequence_number  = entries_.size() + 1;
        e.event_type       = event_type;
        e.actor_id         = actor_id;
        e.subject_model_id = subject_model_id;
        e.key_id_used      = key_id_used;
        e.payload_summary  = payload_summary;
        e.timestamp        = timestamp;
        e.prev_hash        = entries_.empty()
                             ? genesis_hash_
                             : entries_.back().entry_hash;
        e.entry_hash       = sha256_hex(e.canonical());

        // Index by model_id for fast lookup
        if (!subject_model_id.empty())
            by_model_[subject_model_id].push_back(e.sequence_number);

        entries_.push_back(std::move(e));
        return entries_.back().sequence_number;
    }

    // -----------------------------------------------------------------------
    // get_entry: retrieve by sequence number (1-based).
    // -----------------------------------------------------------------------
    const TransparencyEntry& get_entry(uint64_t seq) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (seq == 0 || seq > entries_.size())
            throw std::out_of_range("sequence number out of range");
        return entries_[seq - 1];
    }

    // -----------------------------------------------------------------------
    // entries_for_model: all log entries for a given model_id.
    // -----------------------------------------------------------------------
    std::vector<TransparencyEntry> entries_for_model(
            const std::string& model_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<TransparencyEntry> result;
        auto it = by_model_.find(model_id);
        if (it == by_model_.end()) return result;
        for (uint64_t seq : it->second)
            result.push_back(entries_[seq - 1]);
        return result;
    }

    // -----------------------------------------------------------------------
    // verify_chain: re-derive all entry_hashes and check prev_hash linkage.
    // Returns true if the chain is intact. O(n) — use for audit only.
    // -----------------------------------------------------------------------
    bool verify_chain() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::string expected_prev = genesis_hash_;
        for (const auto& e : entries_) {
            if (e.prev_hash != expected_prev)   return false;
            if (e.entry_hash != sha256_hex(e.canonical())) return false;
            expected_prev = e.entry_hash;
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // head_hash: the hash of the most recent entry.
    // Used by external auditors to checkpoint the log state.
    // -----------------------------------------------------------------------
    std::string head_hash() const {
        std::lock_guard<std::mutex> lk(mu_);
        if (entries_.empty()) return genesis_hash_;
        return entries_.back().entry_hash;
    }

    uint64_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return entries_.size();
    }

    // -----------------------------------------------------------------------
    // make_key_event_logger: returns a KeyEventLogger lambda that writes
    // key rotation events into this transparency log.
    // -----------------------------------------------------------------------
    KeyEventLogger make_key_event_logger(const std::string& registry_actor_id) {
        // Capture by pointer — caller must ensure log outlives the lambda.
        return [this, registry_actor_id](
                const std::string& event_type,
                uint32_t key_id,
                uint64_t timestamp,
                const std::string& actor_id) {
            std::string summary = "key_id=" + std::to_string(key_id)
                                + " state=" + event_type;
            this->append(event_type,
                         actor_id.empty() ? registry_actor_id : actor_id,
                         /*subject_model_id=*/"",
                         key_id,
                         summary,
                         timestamp);
        };
    }

private:
    mutable std::mutex mu_;
    std::vector<TransparencyEntry> entries_;
    std::unordered_map<std::string, std::vector<uint64_t>> by_model_;
    std::string genesis_hash_;
};

} // namespace uml001