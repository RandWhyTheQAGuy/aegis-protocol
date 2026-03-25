#include "aegis/integration/redis_vault_backend.h"

#ifdef AEGIS_ENABLE_REDIS

namespace uml001 {

RedisVaultBackend::RedisVaultBackend(const std::string& connection_string) {
    redis_ = std::make_unique<sw::redis::Redis>(connection_string);
}

bool RedisVaultBackend::store_nonce(const std::string& key, uint64_t expiry_ms) {
    // Distributed nonce cache. Use SET with PX (millisecond expiry) and NX.
    // Use expiry_ms directly as Redis expects milliseconds, and ensure time is sourced from injected clock elsewhere.
    return redis_->set(
        key,
        "1",
        expiry_ms,
        sw::redis::UpdateType::NOT_EXIST
    );
}

bool RedisVaultBackend::is_revoked(const std::string& passport_id) {
    // Check global revocation list in Redis
    return redis_->sismember("aegis:revocation_list", passport_id);
}

void RedisVaultBackend::append_audit_raw(const std::string& serialized_entry) {
    // Push to a Redis Stream for hyperscale event logging
    redis_->xadd("aegis:audit_stream", "*", {{"data", serialized_entry}});
}

} // namespace uml001

#endif // AEGIS_ENABLE_REDIS
