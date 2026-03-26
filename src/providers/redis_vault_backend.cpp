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
#include "uml001/integration/redis_vault_backend.h"

#ifdef AEGIS_ENABLE_REDIS

namespace uml001 {

RedisVaultBackend::RedisVaultBackend(const std::string& connection_string) {
    redis_ = std::make_unique<sw::redis::Redis>(connection_string);
}

bool RedisVaultBackend::store_nonce(const std::string& key, uint64_t expiry_ms) {
    // Distributed nonce cache. Use SET with PX (millisecond expiry) and NX.
    // Use expiry_ms directly as Redis expects milliseconds, and ensure time is sourced from injected clock elsewhere.
    return redis_->set(
        key,
        "1",
        expiry_ms,
        sw::redis::UpdateType::NOT_EXIST
    );
}

bool RedisVaultBackend::is_revoked(const std::string& passport_id) {
    // Check global revocation list in Redis
    return redis_->sismember("aegis:revocation_list", passport_id);
}

void RedisVaultBackend::append_audit_raw(const std::string& serialized_entry) {
    // Push to a Redis Stream for hyperscale event logging
    redis_->xadd("aegis:audit_stream", "*", {{"data", serialized_entry}});
}

} // namespace uml001

#endif // AEGIS_ENABLE_REDIS
