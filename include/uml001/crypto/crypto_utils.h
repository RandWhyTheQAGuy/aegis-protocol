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
#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace uml001 {

// --- Hashing ---
std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data);
std::string sha256_hex(const std::string& input);
std::string hmac_sha256_hex(const std::string& key, const std::string& data);

// --- Randomness ---
std::vector<uint8_t> secure_random_bytes(std::size_t length);
std::string generate_random_bytes_hex(std::size_t n);

// --- Utility ---
void secure_zero(std::vector<uint8_t>& buffer);
bool constant_time_equals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// --- Encoding ---
std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& input);

// --- Hex utilities required for registry verification ---
std::string hex_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> hex_decode(const std::string& hex);

// --- Signing (Ed25519) ---
std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg);
bool ed25519_verify(const std::vector<uint8_t>& pub, const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig);

// --- Authenticated Encryption ---
struct EncryptionResult {
    bool ok = false; // Crucial for the facade logic
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;
};

// Standardized to use vectors for AEAD to avoid string/byte ambiguity
EncryptionResult aes256_gcm_encrypt(const std::vector<uint8_t>& key, 
                                    const std::vector<uint8_t>& plaintext, 
                                    const std::vector<uint8_t>& aad);

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key, 
                                        const std::vector<uint8_t>& ct, 
                                        const std::vector<uint8_t>& nonce, 
                                        const std::vector<uint8_t>& tag, 
                                        const std::vector<uint8_t>& aad);

EncryptionResult chacha20_poly1305_encrypt(const std::vector<uint8_t>& key, 
                                           const std::vector<uint8_t>& plaintext, 
                                           const std::vector<uint8_t>& aad);

std::vector<uint8_t> chacha20_poly1305_decrypt(const std::vector<uint8_t>& key, 
                                               const std::vector<uint8_t>& ct, 
                                               const std::vector<uint8_t>& nonce, 
                                               const std::vector<uint8_t>& tag, 
                                               const std::vector<uint8_t>& aad);

} // namespace uml001