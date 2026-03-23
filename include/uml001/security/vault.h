#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>

namespace uml001 {

class Vault {
public:
    virtual ~Vault() = default;
    virtual bool store(const std::string& key, const std::vector<uint8_t>& data) = 0;
    virtual std::optional<std::vector<uint8_t>> retrieve(const std::string& key) = 0;
};

// High-security storage for long-term keys
class ColdVault : public Vault {
public:
    bool store(const std::string& key, const std::vector<uint8_t>& data) override;
    std::optional<std::vector<uint8_t>> retrieve(const std::string& key) override;
private:
    std::map<std::string, std::vector<uint8_t>> secure_storage_;
};

} // namespace uml001