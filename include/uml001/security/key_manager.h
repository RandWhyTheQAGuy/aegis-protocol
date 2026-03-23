#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace uml001 {
namespace security {

    class KeyManager {
    public:
        KeyManager() = default;
        ~KeyManager();

        KeyManager(const KeyManager&) = delete;
        KeyManager& operator=(const KeyManager&) = delete;

        std::string create_aes_key(const std::string& purpose);
        std::vector<uint8_t> get_key(const std::string& key_id);
        bool revoke_key(const std::string& key_id);

    private:
        std::string generate_uuid();
        
        std::mutex mutex_;
        std::unordered_map<std::string, std::vector<uint8_t>> keys_;
    };

} // namespace security
} // namespace uml001