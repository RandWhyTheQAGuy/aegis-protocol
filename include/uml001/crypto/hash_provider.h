#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace uml001 {
namespace crypto {

    class IHashProvider {
    public:
        virtual ~IHashProvider() = default;

        virtual std::string sha256(const std::string& input) = 0;
        virtual std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& input) = 0;
        virtual std::string sha512(const std::string& input) = 0;
        virtual std::string sha3_256(const std::string& input) = 0;
    };

} // namespace crypto
} // namespace uml001