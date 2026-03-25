/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/security/vault.h"
#include "uml001/crypto/crypto_utils.h"
#include <iostream>

namespace uml001 {

ColdVault::ColdVault(const VaultConfig& cfg)
    : cfg_(cfg) {
}

bool ColdVault::store(const std::string& key, const std::vector<uint8_t>& data) {
    secure_storage_[key] = data;
    return true;
}

std::optional<std::vector<uint8_t>> ColdVault::retrieve(const std::string& key) {
    auto it = secure_storage_.find(key);
    if (it != secure_storage_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void ColdVault::append(const std::string& type, 
                       const std::string& session_id, 
                       const std::string& actor_id,
                       const std::string& payload_hash, 
                       const std::string& metadata, 
                       uint64_t timestamp) {
    VaultEntry entry{
        type,
        session_id,
        actor_id,
        payload_hash,
        metadata,
        timestamp
    };
    entries_.push_back(entry);
    
    // Log entry for auditability
    std::cout << "[VAULT] " << type << " | session=" << session_id 
              << " | actor=" << actor_id 
              << " | hash=" << payload_hash.substr(0, 8) << "..."
              << " | meta=" << metadata << "\n";
}

} // namespace uml001
