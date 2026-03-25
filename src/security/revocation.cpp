/*
 * Copyright 2026 Aegis Protocol Authors
 */

#include "uml001/security/revocation.h"

namespace uml001 {

void RevocationList::propose_revocation(const std::string& model_id, 
                                        const std::string& reason) {
    // TransparencyLog::append(type, event_type, payload, signer)
    log_.append(TransparencyEntry::Type::REVOCATION_PROPOSED, 
                "REVOCATION_PROPOSAL", 
                rec.evidence_hash, 
                rec.revoked_by);
}

void RevocationList::approve_revocation(const std::string& proposal_id) {
    log_.append(TransparencyEntry::Type::REVOCATION_APPROVED, 
                "REVOCATION_APPROVAL", 
                prop.record.evidence_hash, 
                approver_id);

    if (prop.approvers.size() >= threshold_) {
        prop.finalized = true;
        prop.record.revoked_at = clock.now_unix();
        list_.add_revocation(prop.record);

        log_.append(TransparencyEntry::Type::REVOCATION_FINALIZED, 
                    "REVOCATION_FINALIZED", 
                    prop.record.evidence_hash, 
                    "SYSTEM_QUORUM");
    }
}

} // namespace uml001