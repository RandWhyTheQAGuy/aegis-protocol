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
#include <vector>
#include <string>
#include <cstdint>

namespace uml001 {
namespace crypto {

    struct Envelope {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> tag; // Empty for CTR mode
    };

    // --- AEAD Encryption (GCM & ChaCha20) ---
    Envelope encrypt_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {});
    std::vector<uint8_t> decrypt_gcm(const std::vector<uint8_t>& key, const Envelope& env, const std::vector<uint8_t>& aad = {});

    Envelope encrypt_chacha20(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {});
    std::vector<uint8_t> decrypt_chacha20(const std::vector<uint8_t>& key, const Envelope& env, const std::vector<uint8_t>& aad = {});

    // --- Ed25519 Signatures ---
    std::vector<uint8_t> sign_payload(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& payload);
    bool verify_signature(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& payload);

    // --- Utilities ---
    std::string to_base64(const std::vector<uint8_t>& data);
    std::vector<uint8_t> from_base64(const std::string& data);

} // namespace crypto
} // namespace uml001