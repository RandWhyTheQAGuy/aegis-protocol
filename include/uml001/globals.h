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

#include "uml001/core/clock.h"
#include <memory>

namespace uml001 {

// Global clock instance management (singleton pattern)
// These functions are used by main_aegis_protocol.cpp and Python bindings

/**
 * @brief Register a global clock instance for use throughout the system
 */
void init_clock(std::shared_ptr<IClock> clock);

/**
 * @brief Retrieve the registered global clock instance
 */
std::shared_ptr<IClock> get_clock();

/**
 * @brief Get current Unix time via the global clock
 */
uint64_t now_unix();

/**
 * @brief Validate a timestamp against the global clock's safety bounds
 */
bool validate_timestamp(uint64_t timestamp_unix);

} // namespace uml001
