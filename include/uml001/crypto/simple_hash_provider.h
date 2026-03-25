#pragma once
#include "uml001/crypto/hash_provider.h"
#include <string>
#include <vector>
#include <cstdint>

namespace uml001 {
namespace crypto {

class SimpleHashProvider : public IHashProvider {
public:
    static SimpleHashProvider& instance();

    // Overrides from IHashProvider
    std::string sha256(const std::string& input) override;
    std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& input) override;
    std::string sha512(const std::string& input) override;
    std::string sha3_256(const std::string& input) override;

    // Extended functionality (Removed the invalid 'override' keywords)
    std::vector<uint8_t> sha512_raw(const std::vector<uint8_t>& input);
    std::string sha3_512(const std::string& input);
    std::vector<uint8_t> sha3_256_raw(const std::vector<uint8_t>& input);
    std::vector<uint8_t> sha3_512_raw(const std::vector<uint8_t>& input);

private:
    SimpleHashProvider() = default;
    ~SimpleHashProvider() override = default;
    SimpleHashProvider(const SimpleHashProvider&) = delete;
    SimpleHashProvider& operator=(const SimpleHashProvider&) = delete;
};

} // namespace crypto
} // namespace uml001