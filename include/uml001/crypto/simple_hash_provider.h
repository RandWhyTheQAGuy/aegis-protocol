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
#include "uml001/crypto/hash_provider.h"
#include <string>
#include <vector>
#include <cstdint>

namespace uml001 {
namespace crypto {

class SimpleHashProvider : public IHashProvider {
public:
    static SimpleHashProvider& instance();

    // Overrides from IHashProvider
    std::string sha256(const std::string& input) override;
    std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& input) override;
    std::string sha512(const std::string& input) override;
    std::string sha3_256(const std::string& input) override;

    // Extended functionality (Removed the invalid 'override' keywords)
    std::vector<uint8_t> sha512_raw(const std::vector<uint8_t>& input);
    std::string sha3_512(const std::string& input);
    std::vector<uint8_t> sha3_256_raw(const std::vector<uint8_t>& input);
    std::vector<uint8_t> sha3_512_raw(const std::vector<uint8_t>& input);

private:
    SimpleHashProvider() = default;
    ~SimpleHashProvider() override = default;
    SimpleHashProvider(const SimpleHashProvider&) = delete;
    SimpleHashProvider& operator=(const SimpleHashProvider&) = delete;
};

} // namespace crypto
} // namespace uml001