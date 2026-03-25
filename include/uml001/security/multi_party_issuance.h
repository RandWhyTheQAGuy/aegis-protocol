#pragma once
// multi_party_issuance.h  -- UML-001 Multi-Party Passport Issuance
//
// Design:
//   - A passport is not valid until M-of-N designated signers have approved it.
//   - Uses length-prefixed concatenation for the composite signature to ensure
//     cryptographic domain separation and prevent concatenation ambiguity.

#include "uml001/core/passport.h"
#include "uml001/security/transparency_log.h"
#include "uml001/security/key_rotation.h"
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <stdexcept>
#include <algorithm>
#include <cstring> // For memcpy

namespace uml001 {

inline std::string derive_signer_key(const std::string& root_key,
                                     const std::string& signer_id) {
    std::string info = "UML001-SIGNER:" + signer_id;
    return hmac_sha256_hex(root_key, info);
}

enum class QuorumState {
    PENDING, FINALIZED, EXPIRED, REJECTED
};

inline std::string quorum_state_str(QuorumState s) {
    switch (s) {
        case QuorumState::PENDING:   return "PENDING";
        case QuorumState::FINALIZED: return "FINALIZED";
        case QuorumState::EXPIRED:   return "EXPIRED";
        case QuorumState::REJECTED:  return "REJECTED";
        default:                     return "UNKNOWN";
    }
}

struct QuorumRecord {
    std::string              proposal_id;
    SemanticPassport         proposed_passport;
    std::map<std::string, std::string> partial_sigs; 
    std::set<std::string>    rejections;
    QuorumState              state      = QuorumState::PENDING;
    uint64_t                 proposed_at = 0;
    uint64_t                 expires_at  = 0;
    uint32_t                 threshold   = 0;

    bool is_expired(uint64_t now) const {
        return now >= expires_at && state == QuorumState::PENDING;
    }

    bool threshold_met() const {
        return partial_sigs.size() >= threshold;
    }
};

class MultiPartyIssuer {
public:
    MultiPartyIssuer(std::vector<std::string>  signers,
                     uint32_t                  threshold,
                     const std::string&        registry_version,
                     TransparencyLog&          log,
                     uint64_t                  proposal_ttl_seconds = 300)
        : signers_(std::move(signers))
        , threshold_(threshold)
        , registry_version_(registry_version)
        , log_(log)
        , proposal_ttl_(proposal_ttl_seconds) {
        if (threshold_ == 0 || threshold_ > signers_.size())
            throw std::invalid_argument("threshold must be in [1, signers.size()]");
    }

    std::string propose(const std::string&  proposer_id,
                        const std::string&  proposer_root_key,
                        const std::string&  model_id,
                        const std::string&  model_version,
                        const Capabilities& caps,
                        const std::string&  policy_hash,
                        uint64_t            now,
                        uint64_t            passport_ttl_seconds = 86400) {
        std::lock_guard<std::mutex> lk(mu_);
        ensure_signer_authorized(proposer_id);

        SemanticPassport p;
        p.model_id         = model_id;
        p.model_version    = model_version;
        p.registry_version = registry_version_;
        p.capabilities     = caps;
        p.policy_hash      = policy_hash;
        p.issued_at        = now;
        p.expires_at       = now + passport_ttl_seconds;

        std::string proposal_id = sha256_hex(model_id + std::to_string(now));

        QuorumRecord rec;
        rec.proposal_id       = proposal_id;
        rec.proposed_passport = p;
        rec.state             = QuorumState::PENDING;
        rec.proposed_at       = now;
        rec.expires_at        = now + proposal_ttl_;
        rec.threshold         = threshold_;

        std::string signer_key = derive_signer_key(proposer_root_key, proposer_id);
        rec.partial_sigs[proposer_id] = hmac_sha256_hex(signer_key, p.canonical_body());

        proposals_[proposal_id] = std::move(rec);

        log_.append(TransparencyEntry::PASSPORT_ISSUED, proposer_id, model_id, 0,
                    "PROPOSED id=" + proposal_id, now);

        if (threshold_ == 1) finalize_locked(proposal_id, now);

        return proposal_id;
    }

    bool countersign(const std::string& signer_id,
                     const std::string& signer_root_key,
                     const std::string& proposal_id,
                     uint64_t           now) {
        std::lock_guard<std::mutex> lk(mu_);
        ensure_signer_authorized(signer_id);
        auto& rec = get_proposal_locked(proposal_id, now);

        if (rec.partial_sigs.count(signer_id))
            throw std::runtime_error("Already signed");

        std::string signer_key = derive_signer_key(signer_root_key, signer_id);
        rec.partial_sigs[signer_id] = hmac_sha256_hex(signer_key, rec.proposed_passport.canonical_body());

        if (rec.threshold_met()) {
            finalize_locked(proposal_id, now);
            return true;
        }
        return false;
    }

    // ... (reject, expire_stale_proposals, get_finalized_passport remain same) ...

    bool verify_quorum_passport(const SemanticPassport& p, uint64_t now) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (!p.is_valid(now)) return false;

        // In this implementation, we verify against the in-memory proposal record
        for (const auto& [pid, rec] : proposals_) {
            if (rec.proposed_passport.model_id == p.model_id && rec.state == QuorumState::FINALIZED) {
                std::string expected = build_composite(rec.partial_sigs, p.canonical_body());
                return (expected == p.signature);
            }
        }
        return false;
    }

private:
    mutable std::mutex mu_;
    std::vector<std::string>          signers_;
    uint32_t                          threshold_;
    std::string                       registry_version_;
    TransparencyLog&                  log_;
    uint64_t                          proposal_ttl_;
    std::map<std::string, QuorumRecord> proposals_;

    // -----------------------------------------------------------------------
    // FIX: Length-Prefixed Composite Hash
    // -----------------------------------------------------------------------
    static std::string build_composite(
            const std::map<std::string, std::string>& sigs,
            const std::string& canonical_body) {
        
        std::string blob;
        
        auto append_prefixed = [&](const std::string& s) {
            uint64_t len = static_cast<uint64_t>(s.size());
            // Append length as raw bytes (8 bytes, little-endian)
            blob.append(reinterpret_cast<const char*>(&len), sizeof(len));
            blob.append(s);
        };

        // 1. Prefix and append the passport body
        append_prefixed(canonical_body);

        // 2. Prefix and append each signature (ordered by signer_id via map)
        for (const auto& [signer_id, sig_hex] : sigs) {
            append_prefixed(signer_id);
            append_prefixed(sig_hex);
        }

        return sha256_hex(blob);
    }

    void finalize_locked(const std::string& proposal_id, uint64_t now) {
        auto& rec = proposals_.at(proposal_id);
        rec.proposed_passport.signature = build_composite(rec.partial_sigs, rec.proposed_passport.canonical_body());
        rec.state = QuorumState::FINALIZED;
        log_.append(TransparencyEntry::PASSPORT_ISSUED, "quorum", rec.proposed_passport.model_id, 0, "FINALIZED", now);
    }

    // Helper stubs for brevity
    void ensure_signer_authorized(const std::string& id) const { /* ... */ }
    QuorumRecord& get_proposal_locked(const std::string& id, uint64_t now) { return proposals_.at(id); }
};

} // namespace uml001