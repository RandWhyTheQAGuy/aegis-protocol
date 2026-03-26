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
#include <string>
#include <set>

namespace uml001 {

class RevocationList {
public:
    // We pass by reference to ensure the list is tied to a specific log instance
    explicit RevocationList(TransparencyLog& log) : log_(log) {}

    void propose_revocation(const std::string& model_id, const std::string& reason);
    void approve_revocation(const std::string& proposal_id);
    void finalize_revocation(const std::string& model_id);

    bool is_revoked(const std::string& model_id) const {
        return revoked_models_.find(model_id) != revoked_models_.end();
    }

private:
    TransparencyLog& log_;
    std::set<std::string> revoked_models_;
};

} // namespace uml001