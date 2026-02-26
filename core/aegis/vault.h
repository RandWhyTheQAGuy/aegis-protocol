// vault.h
    #pragma once
    #include "passport.h"   // for sha256_hex
    #include "session.h"    // for SessionEvent
    #include <vector>
    #include <sstream>
    #include <stdexcept>

    namespace uml002 {

    struct VaultEntry {
        std::string entry_id;
        std::string prev_hash;
        uint64_t    sequence    = 0;
        uint64_t    timestamp   = 0;
        std::string event_type;
        std::string session_id;
        std::string agent_id;
        std::string payload_hash;
        std::string detail;     // JSON string of event-specific data
        std::string entry_hash;

        std::string canonical() const {
            // Lexicographic key order; exclude entry_hash
            std::ostringstream s;
            s << "agent_id="     << agent_id
              << "&detail="      << detail
              << "&entry_id="    << entry_id
              << "&event_type="  << event_type
              << "&payload_hash="<< payload_hash
              << "&prev_hash="   << prev_hash
              << "&sequence="    << sequence
              << "&session_id="  << session_id
              << "&timestamp="   << timestamp;
            return s.str();
        }

        void finalize() {
            entry_hash = sha256_hex(canonical());
        }

        bool verify() const {
            return sha256_hex(canonical()) == entry_hash;
        }
    };

    // ---------------------------------------------------------------------------
    // ColdAuditVault: append-only, cryptographically chained event log
    // ---------------------------------------------------------------------------
    class ColdAuditVault {
    public:
        ColdAuditVault() : sequence_(0) {}

        // Append a new entry. Returns the entry_hash of the appended entry.
        const std::string& append(const std::string& event_type,
                                  const std::string& session_id,
                                  const std::string& agent_id,
                                  const std::string& payload_hash,
                                  const std::string& detail,
                                  uint64_t           timestamp) {
            VaultEntry entry;
            entry.prev_hash    = entries_.empty()
                                 ? "GENESIS"
                                 : entries_.back().entry_hash;
            entry.sequence     = sequence_++;
            entry.timestamp    = timestamp;
            entry.event_type   = event_type;
            entry.session_id   = session_id;
            entry.agent_id     = agent_id;
            entry.payload_hash = payload_hash;
            entry.detail       = detail;
            entry.entry_id     = sha256_hex(entry.prev_hash +
                                            std::to_string(entry.sequence));
            entry.finalize();
            entries_.push_back(std::move(entry));
            return entries_.back().entry_hash;
        }

        // Verify the integrity of the entire chain.
        // Returns true if all entries are valid and the chain is unbroken.
        bool verify_chain() const {
            std::string expected_prev = "GENESIS";
            for (size_t i = 0; i < entries_.size(); ++i) {
                const auto& e = entries_[i];
                if (!e.verify()) return false;
                if (e.prev_hash != expected_prev) return false;
                if (e.sequence  != static_cast<uint64_t>(i)) return false;
                expected_prev = e.entry_hash;
            }
            return true;
        }

        size_t size() const { return entries_.size(); }
        const VaultEntry& at(size_t i) const { return entries_.at(i); }
        const std::vector<VaultEntry>& entries() const { return entries_; }

    private:
        std::vector<VaultEntry> entries_;
        uint64_t                sequence_;
    };

    } // namespace uml002
