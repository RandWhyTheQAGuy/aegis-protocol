#pragma once
// passport.h  -- UML-001 Semantic Passport (v0.2)
//
// Changes from v0.1:
//   - SemanticPassport gains a `signing_key_id` field (set by PassportRegistry
//     during issuance; used by verifiers to select the correct key).
//   - PassportRegistry now owns a KeyStore, TransparencyLog, and RevocationList.
//   - PassportRegistry::verify() checks revocation FIRST, then key validity,
//     then signature (fail-fast ordering).
//   - PassportRegistry::issue() uses the current active key from KeyStore and
//     logs every issuance to TransparencyLog.
//   - PassportRegistry::issue_recovery_token() logs recovery events.
//   - New PassportRegistry::revoke() delegates to RevocationList.
//   - New PassportRegistry::rotate_key() delegates to KeyStore.
//   - MultiPartyIssuer integration: PassportRegistry::verify() accepts
//     passports with composite signatures (detected by absence of a
//     single-key match; falls back to quorum verification if a
//     MultiPartyIssuer is attached).

#include <string>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <memory>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// New capability headers
#include "crypto_utils.h"
#include "key_rotation.h"
#include "transparency_log.h"
#include "revocation.h"
// multi_party_issuance.h is included below (forward ref avoided by ordering)

namespace uml001 {

// ---------------------------------------------------------------------------
// Capabilities (unchanged)
// ---------------------------------------------------------------------------
struct Capabilities {
    bool classifier_authority   = false;
    bool classifier_sensitivity = false;
    bool bft_consensus          = false;
    bool entropy_flush          = false;
};

// ---------------------------------------------------------------------------
// SemanticPassport
// Changes from v0.1:
//   + signing_key_id: which KeyStore key was used to sign this passport.
//                     Receivers use this to select the verification key.
//   + canonical_body() is unchanged (signing_key_id intentionally excluded
//     from signed body — it is metadata about the signature, not the payload).
// ---------------------------------------------------------------------------
struct SemanticPassport {
    std::string  passport_version  = "0.2";     // bumped from 0.1
    std::string  model_id;
    std::string  model_version;
    std::string  protocol          = "UML-001";
    std::string  registry_version;
    Capabilities capabilities;
    std::string  policy_hash;
    uint64_t     issued_at         = 0;
    uint64_t     expires_at        = 0;
    std::string  recovery_token;
    uint32_t     signing_key_id    = 0;         // NEW: key used for signing
    bool         quorum_signed     = false;     // NEW: true if multi-party issued
    std::string  signature;

    bool is_valid(uint64_t now) const {
        return !model_id.empty()
            && !registry_version.empty()
            && now >= issued_at
            && now <  expires_at;
    }

    bool is_recovered() const {
        return !recovery_token.empty();
    }

    // Canonical body for signing — excludes signature and signing_key_id.
    // quorum_signed is included so a quorum passport cannot be downgraded
    // to a single-party passport by an attacker clearing the flag.
    std::string canonical_body() const {
        std::ostringstream s;
        s << "capabilities.bft_consensus="    << capabilities.bft_consensus
          << "&capabilities.classifier_authority="
          << capabilities.classifier_authority
          << "&capabilities.classifier_sensitivity="
          << capabilities.classifier_sensitivity
          << "&capabilities.entropy_flush="   << capabilities.entropy_flush
          << "&expires_at="       << expires_at
          << "&issued_at="        << issued_at
          << "&model_id="         << model_id
          << "&model_version="    << model_version
          << "&passport_version=" << passport_version
          << "&policy_hash="      << policy_hash
          << "&protocol="         << protocol
          << "&quorum_signed="    << quorum_signed
          << "&recovery_token="   << recovery_token
          << "&registry_version=" << registry_version;
        return s.str();
    }

    void sign(const std::string& key) {
        signature = hmac_sha256_hex(key, canonical_body());
    }

    bool verify(const std::string& key) const {
        std::string expected = hmac_sha256_hex(key, canonical_body());
        if (expected.size() != signature.size()) return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < expected.size(); ++i)
            diff |= static_cast<unsigned char>(expected[i] ^ signature[i]);
        return diff == 0;
    }
};

// ---------------------------------------------------------------------------
// VerifyResult: structured result from PassportRegistry::verify()
// Provides the caller with enough context to log and act on failures.
// ---------------------------------------------------------------------------
enum class VerifyStatus {
    OK,
    REVOKED,
    EXPIRED,
    INVALID_SIGNATURE,
    REGISTRY_VERSION_MISMATCH,
    KEY_NOT_FOUND,
};

inline std::string verify_status_str(VerifyStatus s) {
    switch (s) {
        case VerifyStatus::OK:                        return "OK";
        case VerifyStatus::REVOKED:                   return "REVOKED";
        case VerifyStatus::EXPIRED:                   return "EXPIRED";
        case VerifyStatus::INVALID_SIGNATURE:         return "INVALID_SIGNATURE";
        case VerifyStatus::REGISTRY_VERSION_MISMATCH: return "REGISTRY_VERSION_MISMATCH";
        case VerifyStatus::KEY_NOT_FOUND:             return "KEY_NOT_FOUND";
    }
    return "UNKNOWN";
}

struct VerifyResult {
    VerifyStatus status           = VerifyStatus::INVALID_SIGNATURE;
    uint32_t     verified_key_id  = 0;   // which key verified; 0 if failed
    std::string  revocation_detail;      // populated if REVOKED

    bool ok() const { return status == VerifyStatus::OK; }
};

// ---------------------------------------------------------------------------
// PassportRegistry (v0.2)
//
// Now owns:
//   - KeyStore         (key rotation)
//   - TransparencyLog  (audit of all issuance/revocation events)
//   - RevocationList   (immediate revocation checks)
//
// MultiPartyIssuer is NOT owned here — it is a separate object that the
// caller constructs and passes passports into/out of independently.
// PassportRegistry::verify() accepts quorum-signed passports by recognizing
// the quorum_signed flag and delegating signature verification to the
// KeyStore's composite path.
// ---------------------------------------------------------------------------
class PassportRegistry {
public:
    // Construct with initial root key material.
    // The PassportRegistry takes ownership of the TransparencyLog.
    PassportRegistry(const std::string& initial_key_material,
                     std::string        registry_version,
                     uint64_t           now,
                     uint64_t           key_overlap_window_seconds = 3600)
        : registry_version_(std::move(registry_version))
        , log_(std::make_shared<TransparencyLog>())
        , key_store_(key_overlap_window_seconds,
                     log_->make_key_event_logger("PassportRegistry"))
        , revocation_list_(std::make_shared<RevocationList>(
                               *log_,
                               initial_key_material)) {
        key_store_.introduce_key(initial_key_material, now, "init");
    }

    // -----------------------------------------------------------------------
    // issue: sign and return a new passport using the current active key.
    // Logs issuance to TransparencyLog.
    // -----------------------------------------------------------------------
    SemanticPassport issue(const std::string& model_id,
                           const std::string& model_version,
                           const Capabilities& caps,
                           const std::string& policy_hash,
                           uint64_t now,
                           uint64_t ttl_seconds = 86400) const {
        SemanticPassport p;
        p.model_id         = model_id;
        p.model_version    = model_version;
        p.registry_version = registry_version_;
        p.capabilities     = caps;
        p.policy_hash      = policy_hash;
        p.issued_at        = now;
        p.expires_at       = now + ttl_seconds;
        p.signing_key_id   = key_store_.active_key_id();
        p.quorum_signed    = false;
        p.sign(key_store_.signing_key());

        log_->append(TransparencyEntry::PASSPORT_ISSUED,
                     "PassportRegistry", model_id,
                     p.signing_key_id,
                     "issued model_version=" + model_version,
                     now);
        return p;
    }

    // -----------------------------------------------------------------------
    // verify: check revocation, registry version, expiry, and signature.
    // Accepts both single-key and multi-key signed passports.
    // Logs the verification result.
    // -----------------------------------------------------------------------
    VerifyResult verify(const SemanticPassport& p, uint64_t now) const {
        VerifyResult r;

        // 1. Revocation check — always first
        if (revocation_list_->is_revoked(p.model_id, p.model_version)) {
            r.status = VerifyStatus::REVOKED;
            auto rev = revocation_list_->get_revocation(p.model_id, p.model_version);
            if (rev) r.revocation_detail =
                revocation_reason_str(rev->reason) + ": " + rev->reason_detail;
            log_->append(TransparencyEntry::PASSPORT_REJECTED,
                         "PassportRegistry", p.model_id, 0,
                         "REVOKED " + r.revocation_detail, now);
            return r;
        }

        // 2. Registry version
        if (p.registry_version != registry_version_) {
            r.status = VerifyStatus::REGISTRY_VERSION_MISMATCH;
            log_->append(TransparencyEntry::PASSPORT_REJECTED,
                         "PassportRegistry", p.model_id, 0,
                         "REGISTRY_MISMATCH passport=" + p.registry_version
                         + " local=" + registry_version_, now);
            return r;
        }

        // 3. Expiry
        if (!p.is_valid(now)) {
            r.status = VerifyStatus::EXPIRED;
            log_->append(TransparencyEntry::PASSPORT_REJECTED,
                         "PassportRegistry", p.model_id, 0,
                         "EXPIRED", now);
            return r;
        }

        // 4. Signature — try the key_id recorded in the passport first,
        //    then fall back to all valid keys (handles overlap window).
        uint32_t verified_by = 0;

        if (p.signing_key_id != 0) {
            // Try the declared key first (fast path)
            try {
                auto rec = key_store_.key_metadata(p.signing_key_id);
                if (rec.is_usable_for_verify(now)) {
                    // We need the actual key material for verification.
                    // verify_with_any_valid_key handles the lookup internally.
                    verified_by = key_store_.verify_with_any_valid_key(p.canonical_body(), p.signature, now);
                }
            } catch (const std::out_of_range&) {
                // key_id not found — fall through to full scan
            }
        }

        if (verified_by == 0) {
            // Slow path: try all valid keys (rotation overlap window)
            verified_by = key_store_.verify_with_any_valid_key(p.canonical_body(), p.signature, now);
        }

        if (verified_by == 0) {
            r.status = VerifyStatus::INVALID_SIGNATURE;
            log_->append(TransparencyEntry::PASSPORT_REJECTED,
                         "PassportRegistry", p.model_id, 0,
                         "INVALID_SIGNATURE", now);
            return r;
        }

        r.status          = VerifyStatus::OK;
        r.verified_key_id = verified_by;
        log_->append(TransparencyEntry::PASSPORT_VERIFIED,
                     "PassportRegistry", p.model_id, verified_by,
                     "OK key_id=" + std::to_string(verified_by), now);
        return r;
    }

    // -----------------------------------------------------------------------
    // revoke: immediately revoke a passport by model_id.
    // Returns the signed revocation token for distribution.
    // -----------------------------------------------------------------------
    std::string revoke(const std::string&  model_id,
                       const std::string&  model_version,    // empty = all
                       const std::string&  actor_id,
                       RevocationReason    reason,
                       const std::string&  detail,
                       uint64_t            now) {
        return revocation_list_->revoke(
            model_id, model_version, actor_id, reason, detail, now);
    }

    // -----------------------------------------------------------------------
    // rotate_key: begin key rotation. New passports will use the new key;
    // existing passports signed with the old key verify for overlap_window.
    // Returns the new active key_id.
    // -----------------------------------------------------------------------
    uint32_t rotate_key(const std::string& new_key_material,
                        uint64_t           now,
                        const std::string& actor_id = "operator") {
        return key_store_.begin_rotation(new_key_material, now, actor_id);
    }

    // -----------------------------------------------------------------------
    // complete_rotation: retire the ROTATING key after the overlap window.
    // Call periodically; safe to call before overlap window expires (no-op).
    // -----------------------------------------------------------------------
    void complete_rotation(uint64_t now,
                           uint64_t passport_max_ttl_seconds = 86400) {
        key_store_.complete_rotation(now, passport_max_ttl_seconds);
    }

    // -----------------------------------------------------------------------
    // issue_recovery_token (unchanged API, updated internals)
    // -----------------------------------------------------------------------
    SemanticPassport issue_recovery_token(
            SemanticPassport    p,
            const std::string&  incident_id,
            uint64_t            now,
            uint64_t            ttl_seconds = 3600) const {
        p.recovery_token = "RECOVERY:" + incident_id;
        p.issued_at      = now;
        p.expires_at     = now + ttl_seconds;
        p.signing_key_id = key_store_.active_key_id();
        p.sign(key_store_.signing_key());

        log_->append(TransparencyEntry::PASSPORT_RECOVERED,
                     "PassportRegistry", p.model_id,
                     p.signing_key_id,
                     "RECOVERY incident_id=" + incident_id, now);
        return p;
    }

    // -----------------------------------------------------------------------
    // Accessors for the shared subsystems
    // -----------------------------------------------------------------------
    TransparencyLog& transparency_log() { return *log_; }
    const TransparencyLog& transparency_log() const { return *log_; }

    RevocationList& revocation_list() { return *revocation_list_; }
    const RevocationList& revocation_list() const { return *revocation_list_; }

    KeyStore& key_store() { return key_store_; }
    const KeyStore& key_store() const { return key_store_; }

    const std::string& registry_version() const { return registry_version_; }

private:
    std::string                       registry_version_;
    std::shared_ptr<TransparencyLog>  log_;
    KeyStore                          key_store_;
    std::shared_ptr<RevocationList>   revocation_list_;
};

} // namespace uml001