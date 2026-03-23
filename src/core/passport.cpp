#include "uml001/core/passport.h"
#include "uml001/transparency_log.h"
#include "uml001/security/revocation.h"
#include "uml001/core/clock.h"

namespace uml001 {

Passport PassportRegistry::issue_model_passport(
    const std::string& model_id,
    const std::string& version,
    const Capabilities& caps,
    const std::string& policy_hash,
    uint32_t key_id) 
{
    Passport p;
    p.model_id = model_id;
    p.model_version = version;
    p.capabilities = caps;
    p.policy_hash = policy_hash;
    p.issued_at = clock_.now_unix();
    p.expires_at = p.issued_at + (3600 * 24 * 30);
    p.signing_key_id = key_id;
    
    p.signature = sha256_hex(p.content_hash() + "|SECRET_KEY_V" + std::to_string(key_id));

    log_.append(TransparencyEntry::Type::PASSPORT_ISSUED, 
                "MODEL_PASSPORT_ISSUE", 
                p.content_hash(), 
                "REGISTRY_PRIMARY", 
                clock_);
    return p;
}

bool PassportRegistry::verify(const Passport& passport) {
    std::string p_id = passport.content_hash();
    bool is_revoked = revocation_list_.is_revoked(p_id);
    bool is_expired = (clock_.now_unix() > passport.expires_at);
    
    bool ok = !is_revoked && !is_expired;

    log_.append(ok ? TransparencyEntry::Type::PASSPORT_VERIFIED : TransparencyEntry::Type::PASSPORT_REJECTED,
                ok ? "VERIFY_SUCCESS" : "VERIFY_FAIL",
                p_id,
                "GATEWAY_NODE",
                clock_);
    return ok;
}

} // namespace uml001