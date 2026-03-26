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
#include <memory>
#include <cstdint>
#include <string>
#include <stdexcept>

namespace uml001::security {

/**
 * @brief Supported zero-knowledge proof types.
 */
enum class ZkProofType {
    RANGE_PROOF = 0,
    MEMBERSHIP_PROOF,
    CUSTOM_PROOF
};

/**
 * @brief Abstract Prover interface for zero-knowledge verification.
 */
class Prover {
public:
    virtual ~Prover() = default;

    /**
     * @brief Verify a proof against the given context.
     * @param context Arbitrary string representing the evaluation context.
     * @param proof Binary proof data.
     * @return true if the proof is valid, false otherwise.
     */
    virtual bool verify(const std::string& context, const std::vector<uint8_t>& proof) = 0;
};

/**
 * @brief Factory for creating ZK proof provers.
 */
class ZkProofFactory {
public:
    static std::unique_ptr<Prover> create_prover(ZkProofType type) {
        switch (type) {
            case ZkProofType::RANGE_PROOF:
                return std::make_unique<RangeProver>();
            case ZkProofType::MEMBERSHIP_PROOF:
                return std::make_unique<MembershipProver>();
            case ZkProofType::CUSTOM_PROOF:
                return std::make_unique<CustomProver>();
            default:
                throw std::invalid_argument("Unsupported ZkProofType");
        }
    }

private:
    // Minimal stub provers for build purposes
    class RangeProver : public Prover {
    public:
        bool verify(const std::string&, const std::vector<uint8_t>&) override {
            return true; // Always succeed for now
        }
    };

    class MembershipProver : public Prover {
    public:
        bool verify(const std::string&, const std::vector<uint8_t>&) override {
            return true;
        }
    };

    class CustomProver : public Prover {
    public:
        bool verify(const std::string&, const std::vector<uint8_t>&) override {
            return true;
        }
    };
};

} // namespace uml001::security