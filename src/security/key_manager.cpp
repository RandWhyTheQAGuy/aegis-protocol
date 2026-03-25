#include "uml001/security/key_manager.h"
#include "uml001/crypto/crypto_utils.h"
#include <stdexcept>
#include <algorithm>

namespace uml001 {
namespace security {

    KeyManager::~KeyManager() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : keys_) {
            ::uml001::secure_zero(pair.second.data(), pair.second.size());
        }
        keys_.clear();
    }

    std::string KeyManager::generate_uuid() {
        return ::uml001::generate_random_bytes_hex(16); // Uses your crypto_utils secure RNG
    }

    std::string KeyManager::create_aes_key(const std::string& purpose) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key_id = purpose + "_" + generate_uuid();
        keys_[key_id] = ::uml001::secure_random_bytes(32); // AES-256 requires 32 bytes
        return key_id;
    }

    std::vector<uint8_t> KeyManager::get_key(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(key_id);
        if (it != keys_.end()) {
            return it->second;
        }
        throw std::runtime_error("Key ID not found or revoked: " + key_id);
    }

    bool KeyManager::revoke_key(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(key_id);
        if (it != keys_.end()) {
            ::uml001::secure_zero(it->second.data(), it->second.size()); // Zeroize before destruction
            keys_.erase(it);
            return true;
        }
        return false;
    }

} // namespace security
} // namespace uml001