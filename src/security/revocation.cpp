/*
 * Copyright 2026 Aegis Protocol Authors
 */

#include "uml001/security/revocation.h"

namespace uml001 {

void RevocationList::propose_revocation(const std::string& model_id, 
                                        const std::string& reason) {
    // TransparencyLog::append(type, event_type, payload, signer)
    log_.append(TransparencyEntry::Type::REVOCATION_PROPOSED, 
                "CERT_REVOKE_PROPOSAL", 
                model_id, 
                reason);
}

void RevocationList::approve_revocation(const std::string& proposal_id) {
    log_.append(TransparencyEntry::Type::REVOCATION_APPROVED, 
                "CERT_REVOKE_APPROVAL", 
                proposal_id, 
                "SYSTEM_QUORUM");
}

void RevocationList::finalize_revocation(const std::string& model_id) {
    revoked_models_.insert(model_id);
    log_.append(TransparencyEntry::Type::REVOCATION_FINALIZED, 
                "CERT_REVOKE_FINAL", 
                model_id, 
                "COMMIT_SUCCESS");
}
}

} // namespace uml001