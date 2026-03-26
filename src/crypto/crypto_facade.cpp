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
#include "uml001/crypto/crypto_facade.h"
#include "uml001/crypto/crypto_utils.h"
#include <stdexcept>

namespace uml001 {
namespace crypto {

    Envelope encrypt_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad) {
        // Calling the hardened utility in the parent namespace
        auto res = ::uml001::aes256_gcm_encrypt(key, plaintext, aad);
        if (!res.ok) {
            throw std::runtime_error("AES-256-GCM encryption failed: internal provider error");
        }
        return {res.ciphertext, res.nonce, res.tag};
    }

    std::vector<uint8_t> decrypt_gcm(const std::vector<uint8_t>& key, const Envelope& env, const std::vector<uint8_t>& aad) {
        auto plaintext = ::uml001::aes256_gcm_decrypt(key, env.ciphertext, env.nonce, env.tag, aad);
        
        // Security Check: If ciphertext was provided but plaintext is empty, 
        // it's likely an authentication tag mismatch (AEAD failure).
        if (plaintext.empty() && !env.ciphertext.empty()) {
            throw std::runtime_error("AES-GCM decryption failed: integrity check failed");
        }
        return plaintext;
    }

    Envelope encrypt_chacha20(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad) {
        auto res = ::uml001::chacha20_poly1305_encrypt(key, plaintext, aad);
        if (!res.ok) {
            throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
        }
        return {res.ciphertext, res.nonce, res.tag};
    }

    std::vector<uint8_t> decrypt_chacha20(const std::vector<uint8_t>& key, const Envelope& env, const std::vector<uint8_t>& aad) {
        auto plaintext = ::uml001::chacha20_poly1305_decrypt(key, env.ciphertext, env.nonce, env.tag, aad);
        if (plaintext.empty() && !env.ciphertext.empty()) {
            throw std::runtime_error("ChaCha20-Poly1305 decryption failed: integrity check failed");
        }
        return plaintext;
    }

    // --- Signatures & Encoding ---
    
    std::vector<uint8_t> sign_payload(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& payload) {
        return ::uml001::ed25519_sign(private_key, payload);
    }

    bool verify_signature(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& payload) {
        return ::uml001::ed25519_verify(public_key, payload, signature);
    }

    std::string to_base64(const std::vector<uint8_t>& data) {
        return ::uml001::base64_encode(data);
    }

    std::vector<uint8_t> from_base64(const std::string& data) {
        return ::uml001::base64_decode(data);
    }

} // namespace crypto
} // namespace uml001