#pragma once
// key_rotation.h  -- UML-001 Key Rotation Protocol
//
// Design:
//   - Keys are versioned by a monotonically increasing key_id (uint32_t).
//   - The KeyStore holds all active and retired keys.
//   - A key transitions: ACTIVE -> ROTATING -> RETIRED.
//   - During ROTATING, new passports are signed with the successor key,
//     but verification still accepts the predecessor for a configurable
//     overlap window (default: 1 hour).
//   - Retired keys are kept for audit/verification of historical passports
//     until their last-issued passport's expires_at has passed, after which
//     they may be purged.
//   - Every key event (introduce, rotate, retire) is written to the
//     TransparencyLog (transparency_log.h) before taking effect.

#include "crypto_utils.h"
#include <map>
#include <mutex>
#include <vector>
#include <stdexcept>
#include <chrono>
#include <functional>

namespace uml001 {

// ---------------------------------------------------------------------------
// Key lifecycle state
// ---------------------------------------------------------------------------
enum class KeyState {
    ACTIVE,    // sole signing key; all verifications use this key
    ROTATING,  // successor has been introduced; both keys verify; no new signs
    RETIRED,   // no longer signs; verifies only passports issued before retire_at
    PURGED     // removed from store entirely
};

inline std::string key_state_str(KeyState s) {
    switch (s) {
        case KeyState::ACTIVE:   return "ACTIVE";
        case KeyState::ROTATING: return "ROTATING";
        case KeyState::RETIRED:  return "RETIRED";
        case KeyState::PURGED:   return "PURGED";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// KeyRecord: metadata about one key
// ---------------------------------------------------------------------------
struct KeyRecord {
    uint32_t    key_id       = 0;
    std::string key_material;       // the actual HMAC key bytes
    KeyState    state        = KeyState::ACTIVE;
    uint64_t    introduced_at = 0;  // Unix timestamp
    uint64_t    rotate_at    = 0;   // 0 = not yet scheduled
    uint64_t    retire_at    = 0;   // 0 = not yet retired
    uint64_t    purge_after  = 0;   // 0 = never purge (keep for audit)

    bool is_usable_for_verify(uint64_t now) const {
        if (state == KeyState::PURGED)  return false;
        if (state == KeyState::RETIRED && purge_after > 0 && now > purge_after)
            return false;
        return true;
    }
};

// ---------------------------------------------------------------------------
// TransparencyLogWriter interface (forward decl; implement in transparency_log.h)
// KeyStore calls this on every mutation so the log is always up-to-date.
// ---------------------------------------------------------------------------
using KeyEventLogger = std::function<void(
    const std::string& event_type,   // "KEY_INTRODUCED" | "KEY_ROTATING" | "KEY_RETIRED" | "KEY_PURGED"
    uint32_t key_id,
    uint64_t timestamp,
    const std::string& actor_id      // who triggered the event
)>;

// ---------------------------------------------------------------------------
// KeyStore: thread-safe versioned key store with rotation protocol
// ---------------------------------------------------------------------------
class KeyStore {
public:
    // overlap_window_seconds: how long a ROTATING key still verifies after
    // its successor becomes ACTIVE. Default: 3600 (1 hour).
    explicit KeyStore(uint64_t overlap_window_seconds = 3600,
                      KeyEventLogger logger = nullptr)
        : overlap_window_(overlap_window_seconds)
        , logger_(std::move(logger)) {}

    // -----------------------------------------------------------------------
    // introduce_key: add the first (or a successor) key.
    // Caller must provide a securely generated key_material.
    // -----------------------------------------------------------------------
    uint32_t introduce_key(const std::string& key_material,
                           uint64_t now,
                           const std::string& actor_id = "system") {
        std::lock_guard<std::mutex> lk(mu_);
        if (key_material.size() < 32)
            throw std::invalid_argument("Key material must be >= 32 bytes");

        uint32_t new_id = next_id_++;
        KeyRecord rec;
        rec.key_id        = new_id;
        rec.key_material  = key_material;
        rec.state         = keys_.empty() ? KeyState::ACTIVE : KeyState::ACTIVE;
        rec.introduced_at = now;
        keys_[new_id]     = std::move(rec);
        active_key_id_    = new_id;

        emit_event("KEY_INTRODUCED", new_id, now, actor_id);
        return new_id;
    }

    // -----------------------------------------------------------------------
    // begin_rotation: mark the current ACTIVE key as ROTATING and promote
    // the supplied successor key_material to ACTIVE.
    // Returns the new active key_id.
    // -----------------------------------------------------------------------
    uint32_t begin_rotation(const std::string& new_key_material,
                            uint64_t now,
                            const std::string& actor_id = "system") {
        std::lock_guard<std::mutex> lk(mu_);
        if (keys_.empty())
            throw std::runtime_error("No keys in store; call introduce_key first");

        // Mark current active as ROTATING
        auto& current = keys_.at(active_key_id_);
        if (current.state != KeyState::ACTIVE)
            throw std::runtime_error("Active key is not in ACTIVE state");
        current.state     = KeyState::ROTATING;
        current.rotate_at = now;
        emit_event("KEY_ROTATING", current.key_id, now, actor_id);

        // Introduce successor
        uint32_t new_id  = next_id_++;
        KeyRecord rec;
        rec.key_id        = new_id;
        rec.key_material  = new_key_material;
        rec.state         = KeyState::ACTIVE;
        rec.introduced_at = now;
        keys_[new_id]     = std::move(rec);
        active_key_id_    = new_id;
        emit_event("KEY_INTRODUCED", new_id, now, actor_id);

        return new_id;
    }

    // -----------------------------------------------------------------------
    // complete_rotation: retire the ROTATING key after overlap window expires.
    // Idempotent: safe to call repeatedly; only acts when overlap has elapsed.
    // -----------------------------------------------------------------------
    void complete_rotation(uint64_t now,
                           uint64_t passport_max_ttl_seconds,
                           const std::string& actor_id = "system") {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [id, rec] : keys_) {
            if (rec.state == KeyState::ROTATING
                && now >= rec.rotate_at + overlap_window_) {
                rec.state      = KeyState::RETIRED;
                rec.retire_at  = now;
                // Keep for verification until the longest-lived passport
                // it could have signed has expired.
                rec.purge_after = now + passport_max_ttl_seconds;
                emit_event("KEY_RETIRED", id, now, actor_id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // purge_expired_keys: remove keys whose purge_after has passed.
    // Call periodically (e.g., daily).
    // -----------------------------------------------------------------------
    void purge_expired_keys(uint64_t now,
                            const std::string& actor_id = "system") {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [id, rec] : keys_) {
            if (rec.state == KeyState::RETIRED
                && rec.purge_after > 0
                && now > rec.purge_after) {
                rec.state = KeyState::PURGED;
                rec.key_material.clear(); // zero key material
                emit_event("KEY_PURGED", id, now, actor_id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // signing_key: returns the current active key material for signing.
    // -----------------------------------------------------------------------
    std::string signing_key() const {
        std::lock_guard<std::mutex> lk(mu_);
        return keys_.at(active_key_id_).key_material;
    }

    uint32_t active_key_id() const {
        std::lock_guard<std::mutex> lk(mu_);
        return active_key_id_;
    }

    // -----------------------------------------------------------------------
    // verify_with_any_valid_key: tries all non-purged keys for verification.
    // Takes (canonical_body, signature_hex) rather than SemanticPassport
    // to avoid a circular dependency on passport.h.
    // Returns the key_id that verified, or 0 on failure.
    // -----------------------------------------------------------------------
    uint32_t verify_with_any_valid_key(const std::string& canonical_body,
                                       const std::string& signature_hex,
                                       uint64_t now) const {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& [id, rec] : keys_) {
            if (!rec.is_usable_for_verify(now)) continue;
            std::string expected = hmac_sha256_hex(rec.key_material, canonical_body);
            if (expected.size() != signature_hex.size()) continue;
            unsigned char diff = 0;
            for (size_t i = 0; i < expected.size(); ++i)
                diff |= static_cast<unsigned char>(expected[i] ^ signature_hex[i]);
            if (diff == 0) return id;
        }
        return 0;
    }

    // -----------------------------------------------------------------------
    // key_record: read-only access to a specific key's metadata (no material).
    // -----------------------------------------------------------------------
    KeyRecord key_metadata(uint32_t key_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = keys_.find(key_id);
        if (it == keys_.end())
            throw std::out_of_range("key_id not found");
        KeyRecord copy = it->second;
        copy.key_material.clear(); // never expose material via this path
        return copy;
    }

    size_t key_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return keys_.size();
    }

private:
    mutable std::mutex          mu_;
    std::map<uint32_t, KeyRecord> keys_;
    uint32_t                    active_key_id_ = 0;
    uint32_t                    next_id_       = 1;
    uint64_t                    overlap_window_;
    KeyEventLogger              logger_;

    void emit_event(const std::string& type, uint32_t id,
                    uint64_t ts, const std::string& actor) {
        if (logger_) logger_(type, id, ts, actor);
    }
};

} // namespace uml001