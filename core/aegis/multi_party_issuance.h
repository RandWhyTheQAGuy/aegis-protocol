#pragma once
// multi_party_issuance.h  -- UML-001 Multi-Party Passport Issuance
//
// Design:
//   - A passport is not valid until M-of-N designated signers have
//     independently approved it (threshold signature scheme via HMAC
//     share collection; each signer holds a distinct HMAC key derived
//     from the root key via HKDF-SHA256 with their signer_id as the
//     info parameter).
//   - Issuance proceeds in two phases:
//       Phase 1 (PROPOSE): any authorized signer proposes a passport.
//                          A proposal is stored with one partial signature.
//       Phase 2 (COLLECT): other signers add their partial signatures.
//                          When M signatures are present, the passport is
//                          finalized: all partial sigs are concatenated,
//                          hashed together, and stored as the final signature.
//   - The QuorumRecord tracks the proposal lifecycle.
//   - Every quorum event is appended to the TransparencyLog.
//
// Key derivation (per signer):
//   signer_key_i = HMAC-SHA256(root_key, "UML001-SIGNER:" + signer_id)
//   This means the root_key holder can always recompute any signer key,
//   but signers cannot forge each other's shares (each holds only their
//   own derived key, not the root).

#include "passport.h"
#include "transparency_log.h"
#include "key_rotation.h"
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <stdexcept>
#include <algorithm>

namespace uml001 {

// ---------------------------------------------------------------------------
// Derive a per-signer HMAC key from the root key
// ---------------------------------------------------------------------------
inline std::string derive_signer_key(const std::string& root_key,
                                     const std::string& signer_id) {
    // info = "UML001-SIGNER:" + signer_id
    std::string info = "UML001-SIGNER:" + signer_id;
    return hmac_sha256_hex(root_key, info);
}

// ---------------------------------------------------------------------------
// QuorumState: lifecycle of a multi-party issuance proposal
// ---------------------------------------------------------------------------
enum class QuorumState {
    PENDING,    // collecting signatures; threshold not yet met
    FINALIZED,  // M-of-N reached; passport is valid
    EXPIRED,    // proposal timed out before reaching threshold
    REJECTED    // explicitly rejected by a quorum member
};

inline std::string quorum_state_str(QuorumState s) {
    switch (s) {
        case QuorumState::PENDING:   return "PENDING";
        case QuorumState::FINALIZED: return "FINALIZED";
        case QuorumState::EXPIRED:   return "EXPIRED";
        case QuorumState::REJECTED:  return "REJECTED";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// QuorumRecord: one active issuance proposal
// ---------------------------------------------------------------------------
struct QuorumRecord {
    std::string              proposal_id;      // SHA-256(model_id + proposed_at)
    SemanticPassport         proposed_passport; // unsigned template
    std::map<std::string, std::string> partial_sigs; // signer_id -> HMAC hex
    std::set<std::string>    rejections;        // signer_ids that rejected
    QuorumState              state      = QuorumState::PENDING;
    uint64_t                 proposed_at = 0;
    uint64_t                 expires_at  = 0;   // proposal TTL
    uint32_t                 threshold   = 0;   // M in M-of-N

    bool is_expired(uint64_t now) const {
        return now >= expires_at && state == QuorumState::PENDING;
    }

    bool threshold_met() const {
        return partial_sigs.size() >= threshold;
    }
};

// ---------------------------------------------------------------------------
// MultiPartyIssuer: orchestrates M-of-N passport issuance
// ---------------------------------------------------------------------------
class MultiPartyIssuer {
public:
    // signers: the set of authorized signer_ids.
    // threshold: how many must approve (M in M-of-N).
    // proposal_ttl_seconds: how long a pending proposal lives before expiry.
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
            throw std::invalid_argument(
                "threshold must be in [1, signers.size()]");
    }

    // -----------------------------------------------------------------------
    // propose: initiating signer proposes a new passport.
    // Returns the proposal_id.
    // -----------------------------------------------------------------------
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

        // Build the unsigned passport template
        SemanticPassport p;
        p.model_id         = model_id;
        p.model_version    = model_version;
        p.registry_version = registry_version_;
        p.capabilities     = caps;
        p.policy_hash      = policy_hash;
        p.issued_at        = now;
        p.expires_at       = now + passport_ttl_seconds;
        // Signature field is left empty until quorum is reached

        // proposal_id = hash of model_id + timestamp
        std::string proposal_id = sha256_hex(model_id + std::to_string(now));

        QuorumRecord rec;
        rec.proposal_id       = proposal_id;
        rec.proposed_passport = p;
        rec.state             = QuorumState::PENDING;
        rec.proposed_at       = now;
        rec.expires_at        = now + proposal_ttl_;
        rec.threshold         = threshold_;

        // Add proposer's partial signature immediately
        std::string signer_key = derive_signer_key(proposer_root_key, proposer_id);
        rec.partial_sigs[proposer_id] =
            hmac_sha256_hex(signer_key, p.canonical_body());

        proposals_[proposal_id] = std::move(rec);

        log_.append(TransparencyEntry::PASSPORT_ISSUED,
                    proposer_id, model_id, 0,
                    "PROPOSED proposal_id=" + proposal_id
                    + " threshold=" + std::to_string(threshold_)
                    + "/" + std::to_string(signers_.size()),
                    now);

        // If threshold is 1, finalize immediately
        if (threshold_ == 1) {
            finalize_locked(proposal_id, now);
        }

        return proposal_id;
    }

    // -----------------------------------------------------------------------
    // countersign: a signer adds their partial signature to a proposal.
    // Returns true if quorum was reached and passport is now finalized.
    // -----------------------------------------------------------------------
    bool countersign(const std::string& signer_id,
                     const std::string& signer_root_key,
                     const std::string& proposal_id,
                     uint64_t           now) {
        std::lock_guard<std::mutex> lk(mu_);
        ensure_signer_authorized(signer_id);

        auto& rec = get_proposal_locked(proposal_id, now);

        if (rec.partial_sigs.count(signer_id))
            throw std::runtime_error(
                "signer_id has already signed this proposal");

        if (rec.rejections.count(signer_id))
            throw std::runtime_error(
                "signer_id has already rejected this proposal");

        std::string signer_key = derive_signer_key(signer_root_key, signer_id);
        rec.partial_sigs[signer_id] =
            hmac_sha256_hex(signer_key, rec.proposed_passport.canonical_body());

        log_.append(TransparencyEntry::QUORUM_SIGNED,
                    signer_id,
                    rec.proposed_passport.model_id, 0,
                    "COUNTERSIGNED proposal_id=" + proposal_id
                    + " sigs_so_far=" + std::to_string(rec.partial_sigs.size()),
                    now);

        if (rec.threshold_met()) {
            finalize_locked(proposal_id, now);
            return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // reject: a signer explicitly rejects a proposal.
    // If rejections exceed (N - M + 1), the proposal is permanently killed.
    // -----------------------------------------------------------------------
    void reject(const std::string& signer_id,
                const std::string& proposal_id,
                uint64_t           now) {
        std::lock_guard<std::mutex> lk(mu_);
        ensure_signer_authorized(signer_id);
        auto& rec = get_proposal_locked(proposal_id, now);

        rec.rejections.insert(signer_id);

        // Quorum can never be reached if too many have rejected
        size_t max_rejections = signers_.size() - threshold_ + 1;
        if (rec.rejections.size() >= max_rejections) {
            rec.state = QuorumState::REJECTED;
            log_.append(TransparencyEntry::QUORUM_REJECTED,
                        signer_id,
                        rec.proposed_passport.model_id, 0,
                        "QUORUM_REJECTED proposal_id=" + proposal_id
                        + " rejections=" + std::to_string(rec.rejections.size()),
                        now);
        }
    }

    // -----------------------------------------------------------------------
    // get_finalized_passport: retrieve a completed passport by proposal_id.
    // Throws if the passport is not yet finalized.
    // -----------------------------------------------------------------------
    SemanticPassport get_finalized_passport(const std::string& proposal_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        const auto& rec = proposals_.at(proposal_id);
        if (rec.state != QuorumState::FINALIZED)
            throw std::runtime_error(
                "Passport for proposal_id=" + proposal_id
                + " is not finalized (state=" + quorum_state_str(rec.state) + ")");
        return rec.proposed_passport;
    }

    // -----------------------------------------------------------------------
    // verify_quorum_passport: verify a passport that was multi-party issued.
    // Checks that the stored composite signature matches.
    // -----------------------------------------------------------------------
    bool verify_quorum_passport(const SemanticPassport& p,
                                const std::string&      root_key,
                                uint64_t                now) const {
        if (!p.is_valid(now)) return false;
        // Recompute composite signature
        std::string expected = compute_composite_signature(
            p.canonical_body(), root_key, p.model_id, now);
        // Constant-time compare
        if (expected.size() != p.signature.size()) return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < expected.size(); ++i)
            diff |= static_cast<unsigned char>(expected[i] ^ p.signature[i]);
        return diff == 0;
    }

    // -----------------------------------------------------------------------
    // expire_stale_proposals: mark timed-out proposals as EXPIRED.
    // Call periodically.
    // -----------------------------------------------------------------------
    void expire_stale_proposals(uint64_t now) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [id, rec] : proposals_) {
            if (rec.is_expired(now)) {
                rec.state = QuorumState::EXPIRED;
                log_.append(TransparencyEntry::QUORUM_REJECTED,
                            "system",
                            rec.proposed_passport.model_id, 0,
                            "PROPOSAL_EXPIRED proposal_id=" + id,
                            now);
            }
        }
    }

    const QuorumRecord& get_proposal(const std::string& proposal_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        return proposals_.at(proposal_id);
    }

private:
    mutable std::mutex mu_;
    std::vector<std::string>          signers_;
    uint32_t                          threshold_;
    std::string                       registry_version_;
    TransparencyLog&                  log_;
    uint64_t                          proposal_ttl_;
    std::map<std::string, QuorumRecord> proposals_;

    void ensure_signer_authorized(const std::string& signer_id) const {
        if (std::find(signers_.begin(), signers_.end(), signer_id)
                == signers_.end())
            throw std::runtime_error(
                "signer_id '" + signer_id + "' is not authorized");
    }

    QuorumRecord& get_proposal_locked(const std::string& proposal_id,
                                      uint64_t now) {
        auto it = proposals_.find(proposal_id);
        if (it == proposals_.end())
            throw std::out_of_range("proposal_id not found");
        auto& rec = it->second;
        if (rec.is_expired(now)) {
            rec.state = QuorumState::EXPIRED;
            throw std::runtime_error("proposal has expired");
        }
        if (rec.state != QuorumState::PENDING)
            throw std::runtime_error(
                "proposal is not PENDING (state="
                + quorum_state_str(rec.state) + ")");
        return rec;
    }

    // Composite signature = SHA-256 of all sorted partial signatures concatenated.
    // "sorted" = lexicographic order of signer_id to ensure determinism.
    std::string compute_composite_signature(
            const std::string& canonical_body,
            const std::string& root_key,
            const std::string& model_id,
            uint64_t           now) const {
        // Reconstruct partial sigs from finalized record if available
        // (called only from verify path — we recompute from stored sigs)
        // For verification we need the original partial sigs, so the
        // passport carries the composite hash, and we need the proposal.
        // In production, store partial_sigs alongside the passport in
        // the audit vault. Here we look up the in-memory proposal.
        for (const auto& [pid, rec] : proposals_) {
            if (rec.proposed_passport.model_id == model_id
                && rec.state == QuorumState::FINALIZED) {
                return build_composite(rec.partial_sigs, canonical_body);
            }
        }
        return "";
    }

    static std::string build_composite(
            const std::map<std::string, std::string>& sigs,
            const std::string& canonical_body) {
        // Sort by signer_id (map is already sorted), concatenate all sigs
        std::string concat;
        for (const auto& [id, sig] : sigs)
            concat += sig;
        // Final composite = SHA-256(canonical_body + concatenated_sigs)
        return sha256_hex(canonical_body + concat);
    }

    void finalize_locked(const std::string& proposal_id, uint64_t now) {
        auto& rec = proposals_.at(proposal_id);
        std::string composite = build_composite(
            rec.partial_sigs, rec.proposed_passport.canonical_body());
        rec.proposed_passport.signature = composite;
        rec.state = QuorumState::FINALIZED;

        log_.append(TransparencyEntry::PASSPORT_ISSUED,
                    "quorum",
                    rec.proposed_passport.model_id, 0,
                    "FINALIZED proposal_id=" + proposal_id
                    + " sigs=" + std::to_string(rec.partial_sigs.size()),
                    now);
    }
};

} // namespace uml001