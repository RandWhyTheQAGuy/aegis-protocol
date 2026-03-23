#include "uml001/security/revocation.h"

namespace uml001 {

void MultiPartyRevocationController::propose_revocation(const RevocationRecord& rec, IClock& clock) {
    if (proposals_.count(rec.passport_id)) return;

    ProposalState state;
    state.record = rec;
    proposals_[rec.passport_id] = state;

    log_.append(TransparencyEntry::Type::REVOCATION_PROPOSED, 
                "REVOCATION_PROPOSAL", 
                rec.evidence_hash, 
                rec.revoked_by, 
                clock);
}

void MultiPartyRevocationController::approve_revocation(const std::string& passport_id, 
                                                       const std::string& approver_id, 
                                                       IClock& clock) {
    if (!proposals_.count(passport_id)) return;
    
    auto& prop = proposals_[passport_id];
    if (prop.finalized) return;

    prop.approvers.insert(approver_id);

    log_.append(TransparencyEntry::Type::REVOCATION_APPROVED, 
                "REVOCATION_APPROVAL", 
                prop.record.evidence_hash, 
                approver_id, 
                clock);

    if (prop.approvers.size() >= threshold_) {
        prop.finalized = true;
        prop.record.revoked_at = clock.now_unix();
        list_.add_revocation(prop.record);

        log_.append(TransparencyEntry::Type::REVOCATION_FINALIZED, 
                    "REVOCATION_FINALIZED", 
                    prop.record.evidence_hash, 
                    "SYSTEM_QUORUM", 
                    clock);
    }
}

} // namespace uml001