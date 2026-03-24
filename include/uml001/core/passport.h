/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

#include "uml001/crypto/crypto_utils.h"
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <memory>

namespace uml001 {

// Forward declarations to break circular dependencies
class IClock;
class TransparencyLog;
class RevocationList;

enum class PassportStatus {
    INACTIVE,
    ACTIVE,
    REVOKED
};

struct Capabilities {
    bool classifier_authority = false;
    bool classifier_sensitivity = false;
    bool bft_consensus = false;
    bool entropy_flush = false;

    std::string serialize() const {
        return (classifier_authority ? "1" : "0") +
               std::string(classifier_sensitivity ? "1" : "0") +
               (bft_consensus ? "1" : "0") +
               (entropy_flush ? "1" : "0");
    }
};

struct Passport {
    std::string model_id;
    std::string model_version;
    Capabilities capabilities;
    std::string policy_hash;
    
    // Core timing and status fields
    uint64_t issued_at = 0; 
    uint64_t expires_at = 0;
    PassportStatus status = PassportStatus::INACTIVE; 

    uint32_t signing_key_id = 0;
    std::string signature;
    std::optional<std::string> recovery_token;

    /**
     * @brief Transitions passport to ACTIVE and sets timing bounds.
     */
    void issue(std::shared_ptr<IClock> clock, uint64_t duration_sec = 3600);

    /**
     * @brief Generates a unique hash of the passport metadata for signing/verification.
     */
    std::string content_hash() const {
        std::string raw = model_id + "|" + model_version + "|" + 
                          capabilities.serialize() + "|" + 
                          policy_hash + "|" + 
                          std::to_string(issued_at) + "|" + 
                          std::to_string(expires_at);
        return sha256_hex(raw);
    }
};

class PassportRegistry {
public:
    PassportRegistry(TransparencyLog& log, RevocationList& list, IClock& clock)
        : log_(log), revocation_list_(list), clock_(clock) {}

    Passport issue_model_passport(
        const std::string& model_id,
        const std::string& version,
        const Capabilities& caps,
        const std::string& policy_hash,
        uint32_t key_id
    );
    
    bool verify(const Passport& passport);

private:
    TransparencyLog& log_;
    RevocationList&  revocation_list_;
    IClock&          clock_;
};

} // namespace uml001