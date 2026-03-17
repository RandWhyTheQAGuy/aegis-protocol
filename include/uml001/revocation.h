#pragma once
// revocation.h  -- UML-001 Revocation Channel
//
// Design:
//   - Revocations are stored in a RevocationList keyed by model_id.
//   - Each revocation record captures: the revoking actor, a reason code,
//     a timestamp, and a signed revocation token (so receivers can verify
//     the revocation itself was legitimately issued).
//   - Revocation is immediate: once a model_id is in the list, any
//     passport for that model_id is invalid regardless of its expires_at.
//   - Revocations are NEVER removed (append-only). A re-issued passport
//     after an incident uses a new model_id or a recovery_token path.
//   - The PassportRegistry::verify() path checks the RevocationList before
//     checking signature or expiry.
//   - Every revocation is appended to the TransparencyLog.
//   - Partial revocation: a specific model_version can be revoked without
//     revoking all versions of a model_id. If model_version is empty,
//     the revocation applies to all versions.

#include "crypto_utils.h"
#include "transparency_log.h"

#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>
#include <optional>

namespace uml001 {

// ---------------------------------------------------------------------------
// RevocationReason: machine-readable reason code
// ---------------------------------------------------------------------------
enum class RevocationReason {
    KEY_COMPROMISE,         // signing key was compromised
    POLICY_VIOLATION,       // agent violated policy rules
    INCIDENT_RESPONSE,      // security incident; broad revocation
    VERSION_SUPERSEDED,     // this version is replaced by a newer one
    OPERATOR_REQUEST,       // manual operator action
    WARP_SCORE_THRESHOLD,   // Warp Score exceeded permanent ban threshold
};

inline std::string revocation_reason_str(RevocationReason r) {
    switch (r) {
        case RevocationReason::KEY_COMPROMISE:       return "KEY_COMPROMISE";
        case RevocationReason::POLICY_VIOLATION:     return "POLICY_VIOLATION";
        case RevocationReason::INCIDENT_RESPONSE:    return "INCIDENT_RESPONSE";
        case RevocationReason::VERSION_SUPERSEDED:   return "VERSION_SUPERSEDED";
        case RevocationReason::OPERATOR_REQUEST:     return "OPERATOR_REQUEST";
        case RevocationReason::WARP_SCORE_THRESHOLD: return "WARP_SCORE_THRESHOLD";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// RevocationRecord: one immutable revocation entry
// ---------------------------------------------------------------------------
struct RevocationRecord {
    std::string      model_id;
    std::string      model_version;    // empty = all versions
    std::string      revoking_actor;
    RevocationReason reason;
    std::string      reason_detail;    // free-text elaboration
    uint64_t         revoked_at = 0;   // Unix timestamp
    std::string      revocation_token; // HMAC-SHA256 signed token
    bool             scope_all_versions = false; // true when model_version empty

    // Canonical form for signing the revocation token
    std::string canonical() const {
        std::ostringstream s;
        s << "model_id="        << model_id
          << "&model_version="  << model_version
          << "&reason="         << revocation_reason_str(reason)
          << "&revoked_at="     << revoked_at
          << "&revoking_actor=" << revoking_actor;
        return s.str();
    }

    // Check whether this revocation applies to a given model_id / model_version pair
    bool applies_to(const std::string& p_model_id,
                    const std::string& p_model_version) const {
        if (p_model_id != model_id) return false;
        if (scope_all_versions)     return true;
        return p_model_version == model_version;
    }
};

// ---------------------------------------------------------------------------
// RevocationList: the append-only revocation store
// ---------------------------------------------------------------------------
class RevocationList {
public:
    RevocationList(TransparencyLog& log, const std::string& signing_key)
        : log_(log), signing_key_(signing_key) {}

    // -----------------------------------------------------------------------
    // revoke: add a revocation. Returns the signed revocation token.
    // -----------------------------------------------------------------------
    std::string revoke(const std::string&  model_id,
                       const std::string&  model_version,   // empty = all
                       const std::string&  revoking_actor,
                       RevocationReason    reason,
                       const std::string&  reason_detail,
                       uint64_t            now) {
        std::lock_guard<std::mutex> lk(mu_);

        RevocationRecord rec;
        rec.model_id           = model_id;
        rec.model_version      = model_version;
        rec.revoking_actor     = revoking_actor;
        rec.reason             = reason;
        rec.reason_detail      = reason_detail;
        rec.revoked_at         = now;
        rec.scope_all_versions = model_version.empty();
        rec.revocation_token   = hmac_sha256_hex(signing_key_, rec.canonical());

        records_[model_id].push_back(rec);

        log_.append(TransparencyEntry::PASSPORT_REVOKED,
                    revoking_actor, model_id, 0,
                    "REVOKED model_version="
                    + (model_version.empty() ? "*" : model_version)
                    + " reason=" + revocation_reason_str(reason)
                    + " detail=" + reason_detail,
                    now);

        return rec.revocation_token;
    }

    // -----------------------------------------------------------------------
    // is_revoked: check whether a passport is revoked.
    // -----------------------------------------------------------------------
    bool is_revoked(const std::string& model_id,
                    const std::string& model_version) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = records_.find(model_id);
        if (it == records_.end()) return false;
        for (const auto& rec : it->second) {
            if (rec.applies_to(model_id, model_version)) return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // revocation_reason: returns the first matching revocation reason,
    // or nullopt if not revoked.
    // -----------------------------------------------------------------------
    std::optional<RevocationRecord> get_revocation(
            const std::string& model_id,
            const std::string& model_version) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = records_.find(model_id);
        if (it == records_.end()) return std::nullopt;
        for (const auto& rec : it->second) {
            if (rec.applies_to(model_id, model_version)) return rec;
        }
        return std::nullopt;
    }

    // -----------------------------------------------------------------------
    // verify_revocation_token: verify a received revocation record is
    // legitimately signed by the registry's signing key.
    // -----------------------------------------------------------------------
    bool verify_revocation_token(const RevocationRecord& rec) const {
        std::string expected = hmac_sha256_hex(signing_key_, rec.canonical());
        if (expected.size() != rec.revocation_token.size()) return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < expected.size(); ++i)
            diff |= static_cast<unsigned char>(
                expected[i] ^ rec.revocation_token[i]);
        return diff == 0;
    }

    // -----------------------------------------------------------------------
    // all_revocations_for_model: audit helper.
    // -----------------------------------------------------------------------
    std::vector<RevocationRecord> all_revocations_for_model(
            const std::string& model_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = records_.find(model_id);
        if (it == records_.end()) return {};
        return it->second;
    }

    size_t total_revocations() const {
        std::lock_guard<std::mutex> lk(mu_);
        size_t n = 0;
        for (const auto& [id, v] : records_) n += v.size();
        return n;
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::vector<RevocationRecord>> records_;
    TransparencyLog& log_;
    std::string      signing_key_;
};

} // namespace uml001