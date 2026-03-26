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
#include "uml001/crypto/simple_hash_provider.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace uml001 {
namespace crypto {

// Utility for hex encoding
static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

SimpleHashProvider& SimpleHashProvider::instance() {
    static SimpleHashProvider inst;
    return inst;
}

// SHA256 Implementations
std::vector<uint8_t> SimpleHashProvider::sha256_raw(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(input.data(), input.size(), hash.data())) {
        throw std::runtime_error("SHA256 computation failed");
    }
    return hash;
}

std::string SimpleHashProvider::sha256(const std::string& input) {
    std::vector<uint8_t> raw(input.begin(), input.end());
    return bytes_to_hex(sha256_raw(raw));
}

// SHA512 Implementations
std::vector<uint8_t> SimpleHashProvider::sha512_raw(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);
    if (!SHA512(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash.data())) {
        throw std::runtime_error("SHA512 computation failed");
    }
    return hash;
}

std::string SimpleHashProvider::sha512(const std::string& input) {
    std::vector<uint8_t> raw(input.begin(), input.end());
    return bytes_to_hex(sha512_raw(raw));
}

// SHA3-256 Implementations
std::vector<uint8_t> SimpleHashProvider::sha3_256_raw(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA3-256 computation failed");
    }
    EVP_MD_CTX_free(ctx);
    return hash;
}

std::string SimpleHashProvider::sha3_256(const std::string& input) {
    std::vector<uint8_t> raw(input.begin(), input.end());
    return bytes_to_hex(sha3_256_raw(raw));
}

// SHA3-512 Implementations
std::vector<uint8_t> SimpleHashProvider::sha3_512_raw(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> hash(64);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA3-512 computation failed");
    }
    EVP_MD_CTX_free(ctx);
    return hash;
}

std::string SimpleHashProvider::sha3_512(const std::string& input) {
    std::vector<uint8_t> raw(input.begin(), input.end());
    return bytes_to_hex(sha3_512_raw(raw));
}

} // namespace crypto
} // namespace uml001