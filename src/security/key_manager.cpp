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
#include "uml001/security/key_manager.h"
#include "uml001/crypto/crypto_utils.h"
#include <stdexcept>
#include <algorithm>

namespace uml001 {
namespace security {

    KeyManager::~KeyManager() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : keys_) {
            ::uml001::secure_zero(pair.second); // ✅ FIXED
        }
        keys_.clear();
    }

    std::string KeyManager::generate_uuid() {
        return ::uml001::generate_random_bytes_hex(16);
    }

    std::string KeyManager::create_aes_key(const std::string& purpose) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key_id = purpose + "_" + generate_uuid();
        keys_[key_id] = ::uml001::secure_random_bytes(32);
        return key_id;
    }

    std::vector<uint8_t> KeyManager::get_key(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(key_id);
        if (it != keys_.end()) {
            return it->second;
        }
        throw std::runtime_error("Key ID not found or revoked: " + key_id);
    }

    bool KeyManager::revoke_key(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(key_id);
        if (it != keys_.end()) {
            ::uml001::secure_zero(it->second); // ✅ FIXED
            keys_.erase(it);
            return true;
        }
        return false;
    }

} // namespace security
} // namespace uml001