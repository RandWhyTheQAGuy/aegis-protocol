#pragma once
#include "uml001/ivault_backend.h"
#include <sw/redis++/redis++.h> // redis-plus-plus as per plan

namespace uml001 {

class RedisVaultBackend : public IVaultBackend {
public:
    explicit RedisVaultBackend(const std::string& connection_string);
    
    bool store_nonce(const std::string& key, uint64_t expiry_ms) override;
    bool is_revoked(const std::string& passport_id) override;
    void append_audit_raw(const std::string& serialized_entry) override;

private:
    std::unique_ptr<sw::redis::Redis> redis_;
};

} // namespace uml001