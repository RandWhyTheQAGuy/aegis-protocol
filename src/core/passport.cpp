#include "uml001/core/passport.h"
#include "uml001/security/transparency_log.h"
#include "uml001/core/clock.h" // Ensure the full definition of IClock is visible
#include <iostream>
#include <stdexcept>

namespace uml001 {

void Passport::issue(std::shared_ptr<IClock> clock) {
    if (!clock) {
        throw std::runtime_error("Cannot issue passport without a trusted clock.");
    }
    
    // Updated to match the header field 'issued_at'
    this->issued_at = clock->now_unix();
    this->status = PassportStatus::ACTIVE;
    
    std::cout << "[Passport] Issued new passport for model " << model_id 
              << " at BFT Time: " << this->issued_at << std::endl;
}

VerifyResult PassportRegistry::verify(const Passport& passport) const {
    VerifyResult result;
    
    // Check if passport has expired
    uint64_t now = clock_.now_unix();
    if (passport.expires_at < now) {
        result.status = VerifyStatus::EXPIRED;
        return result;
    }
    
    // Check if passport is active
    if (passport.status != PassportStatus::ACTIVE) {
        result.status = VerifyStatus::INCOMPATIBLE;
        return result;
    }
    
    // Check if passport is revoked
    // (This would typically check the revocation_list_)
    if (passport.status == PassportStatus::REVOKED) {
        result.status = VerifyStatus::REVOKED;
        return result;
    }
    
    // Verification successful
    result.status = VerifyStatus::OK;
    result.verified_key_id = passport.signing_key_id;
    result.recovered = passport.is_recovered();
    result.confidence = 1.0f;
    
    return result;
}

Passport PassportRegistry::issue_model_passport(
    const std::string& model_id,
    const std::string& version,
    const Capabilities& caps,
    const std::string& policy_hash,
    uint32_t key_id
) {
    Passport p;
    p.model_id       = model_id;
    p.model_version  = version;
    p.capabilities   = caps;
    p.policy_hash    = policy_hash;
    p.issued_at      = clock_.now_unix();
    p.expires_at     = p.issued_at + 86400;
    p.status         = PassportStatus::ACTIVE;
    p.signing_key_id = key_id;
    p.signing_key_material = "default-signing-key";
    p.registry_version = "0.1.0";
    p.signature      = hmac_sha256_hex(p.signing_key_material, p.content_hash());

    log_.append(TransparencyEntry::Type::PASSPORT_ISSUED,
                "PASSPORT_ISSUED",
                p.content_hash(),
                std::to_string(key_id));

    return p;
}

} // namespace uml001