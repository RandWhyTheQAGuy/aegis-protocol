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
#include <string>
#include <vector>
#include <cstdint>

namespace uml001 {
namespace crypto {

    // ------------------------------------------------------------------------
    // IHashProvider Base Interface
    // ------------------------------------------------------------------------
    class IHashProvider {
    public:
        virtual ~IHashProvider() = default;

        virtual std::string sha256(const std::string& input) = 0;
        virtual std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& input) = 0;
        virtual std::string sha512(const std::string& input) = 0;
        virtual std::string sha3_256(const std::string& input) = 0;
    };

    // ------------------------------------------------------------------------
    // HSMHashProvider Declaration (Previously missing)
    // ------------------------------------------------------------------------
    class HSMHashProvider : public IHashProvider {
    public:
        std::string sha256(const std::string& data) override;
        std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& input) override;
        std::string sha512(const std::string& input) override;
        std::string sha3_256(const std::string& input) override;
    };

} // namespace crypto
} // namespace uml001