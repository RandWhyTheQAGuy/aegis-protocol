/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/core/passport.h"
#include "uml001/core/clock.h"
#include <iostream>
#include <stdexcept>

namespace uml001 {

void Passport::issue(std::shared_ptr<IClock> clock, uint64_t duration_sec) {
    if (!clock) {
        throw std::runtime_error("Cannot issue passport without a trusted clock.");
    }
    
    this->issued_at = clock->now_unix();
    this->expires_at = this->issued_at + duration_sec;
    this->status = PassportStatus::ACTIVE;
    
    std::cout << "[Passport] Issued new passport for model " << model_id 
              << " at BFT Time: " << this->issued_at 
              << " (Expires: " << this->expires_at << ")" << std::endl;
}

Passport PassportRegistry::issue_model_passport(
    const std::string& model_id,
    const std::string& version,
    const Capabilities& caps,
    const std::string& policy_hash,
    uint32_t key_id) {
    
    Passport p;
    p.model_id = model_id;
    p.model_version = version;
    p.capabilities = caps;
    p.policy_hash = policy_hash;
    p.signing_key_id = key_id;
    
    // Auto-issue upon registration using the registry's clock
    // We wrap the reference in a shared_ptr with a no-op deleter for the issue call
    auto clock_ptr = std::shared_ptr<IClock>(&clock_, [](IClock*){});
    p.issue(clock_ptr);
    
    return p;
}

bool PassportRegistry::verify(const Passport& passport) {
    if (passport.status != PassportStatus::ACTIVE) return false;
    if (clock_.now_unix() > passport.expires_at) return false;
    
    // Cryptographic signature verification logic would go here
    return true;
}

} // namespace uml001