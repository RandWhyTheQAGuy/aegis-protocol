/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
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
#include "uml001/security/vault.h"
#include "uml001/crypto/crypto_utils.h"

#include <iostream>
#include <stdexcept>

namespace uml001 {

ColdVault::ColdVault(const VaultConfig& cfg)
    : cfg_(cfg) {
}

bool ColdVault::store(const std::string& key, const std::vector<uint8_t>& data) {
    secure_storage_[key] = data;
    return true;
}

std::optional<std::vector<uint8_t>> ColdVault::retrieve(const std::string& key) {
    auto it = secure_storage_.find(key);
    if (it != secure_storage_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void ColdVault::append(const std::string& type, 
                       const std::string& session_id, 
                       const std::string& actor_id,
                       const std::string& payload_hash, 
                       const std::string& metadata, 
                       uint64_t timestamp) {
    VaultEntry entry{
        type,
        session_id,
        actor_id,
        payload_hash,
        metadata,
        timestamp
    };
    entries_.push_back(entry);
    
    // Log entry for auditability
    std::cout << "[VAULT] " << type << " | session=" << session_id 
              << " | actor=" << actor_id 
              << " | hash=" << payload_hash.substr(0, 8) << "..."
              << " | meta=" << metadata << "\n";
}

// -----------------------------
// V1.3 CSP Operations
// -----------------------------

// Signing key material is expected to be stored under:
//   "csp:key:<key_id>"
// The message_hash is assumed to be a hex-encoded digest of the payload.
// We derive a signature as: sha256_hex(secret || "|" || message_hash)
std::string ColdVault::sign(uint32_t key_id, const std::string& message_hash) {
    const std::string key_name = "csp:key:" + std::to_string(key_id);
    auto it = secure_storage_.find(key_name);
    if (it == secure_storage_.end()) {
        throw std::runtime_error("ColdVault::sign: signing key not found for id=" + std::to_string(key_id));
    }

    const std::vector<uint8_t>& secret_bytes = it->second;
    std::string secret_str(secret_bytes.begin(), secret_bytes.end());

    // Derive a deterministic signature from stored secret and message hash
    std::string material = secret_str + "|" + message_hash;
    return sha256_hex(material);
}

// Public key material is expected to be stored under:
//   "csp:pub:" + key_id
// If not present, an empty vector is returned.
std::vector<uint8_t> ColdVault::retrieve_public_key(uint32_t key_id) {
    const std::string key_name = "csp:pub:" + std::to_string(key_id);
    auto it = secure_storage_.find(key_name);
    if (it == secure_storage_.end()) {
        return {};
    }
    return it->second;
}

// Peer verification is based on membership in the known_peers_ set.
// This allows higher-level systems to manage the trust boundary explicitly.
bool ColdVault::verify_peer(const std::string& node_id) const {
    return known_peers_.find(node_id) != known_peers_.end();
}

// Management of the Trust Boundary
void ColdVault::add_known_peer(const std::string& node_id) {
    known_peers_.insert(node_id);
}

} // namespace uml001
