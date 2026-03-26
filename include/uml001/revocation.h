/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Gary Gray (github.com/<your-github-handle>)
 *
 * The Aegis Protocol defines a distributed trust and identity framework
 * based on cryptographically verifiable Semantic Passports, capability
 * enforcement, and transparency logging for auditable system behavior.
 *
 * Core components include:
 *   - Semantic Passports: verifiable identity and capability attestations
 *   - Transparency Log: append-only cryptographic audit trail of system events
 *   - Revocation System: deterministic invalidation of compromised or expired identities
 *   - Passport Registry: issuance and verification authority for trusted entities
 *
 * This framework is designed for open standardization, interoperability,
 * and production-grade use in distributed identity, AI systems, and
 * verifiable authorization infrastructures.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for research, verifiable systems design,
 * and deployment in security-critical distributed environments.
 */
#pragma once

#include "uml001/security/transparency_log.h"
#include "uml001/core/clock.h"
#include <string>
#include <vector>
#include <map>
#include <set>

namespace uml001 {

enum class RevocationReason { COMPROMISED_KEY, USER_REQUEST, POLICY_VIOLATION, MULTI_PARTY_DECISION, OTHER };
enum class RevocationMode { RICH, MULTI_PARTY };

struct RevocationRecord {
    std::string passport_id;
    uint64_t    revoked_at = 0;
    RevocationReason reason = RevocationReason::OTHER;
    std::string evidence_hash;
    std::string revoked_by;
};

struct ProposalState {
    RevocationRecord record;
    std::set<std::string> approvers;
    bool finalized = false;
};

class RevocationList {
public:
    void add_revocation(const RevocationRecord& rec) { records_[rec.passport_id] = rec; }
    bool is_revoked(const std::string& id) const { return records_.find(id) != records_.end(); }

private:
    std::map<std::string, RevocationRecord> records_;
};

class MultiPartyRevocationController {
public:
    MultiPartyRevocationController(TransparencyLog& log, RevocationList& list, std::size_t threshold)
        : log_(log), list_(list), threshold_(threshold) {}

    void propose_revocation(const RevocationRecord& rec, IClock& clock);
    void approve_revocation(const std::string& passport_id, const std::string& approver_id, IClock& clock);

private:
    TransparencyLog& log_;
    RevocationList&  list_;
    std::size_t      threshold_;
    std::map<std::string, ProposalState> proposals_;
};

}