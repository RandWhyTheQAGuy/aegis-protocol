#pragma once
#include <string>
#include <vector>

namespace uml001 {

/**
 * @brief Interface for distributed backends (Redis, SQL, etc.)
 */
class IVaultBackend {
public:
    virtual ~IVaultBackend() = default;
    virtual bool store_nonce(const std::string& key, uint64_t expiry_ms) = 0;
    virtual bool is_revoked(const std::string& passport_id) = 0;
    virtual void append_audit_raw(const std::string& serialized_entry) = 0;
};

} // namespace uml001