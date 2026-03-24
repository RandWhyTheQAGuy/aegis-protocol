/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/core/policy.h"
#include "uml001/core/temporal_state.h"
#include "uml001/crypto/crypto_utils.h"
#include <sstream>

namespace uml001 {

/**
 * @brief Logic for write-access based on BFT Quorum/Clock state.
 */
bool allow_write(TemporalState state) {
    return state == TemporalState::SYNCHRONIZED ||
           state == TemporalState::CACHED;
}

/**
 * @brief Logic for read-access based on BFT Quorum/Clock state.
 */
bool allow_read(TemporalState state) {
    return state != TemporalState::UNTRUSTED;
}

/**
 * @brief Generates a deterministic hash of the policy for integrity checks.
 */
std::string Policy::compute_hash() const {
    std::stringstream ss;
    ss << policy_id << ":" << version << "|";
    
    for (const auto& constraint : constraints) {
        ss << constraint.resource_id << ":" 
           << constraint.action << ":" 
           << (constraint.allowed ? "1" : "0") << ";";
    }
    
    return sha256_hex(ss.str());
}

} // namespace uml001