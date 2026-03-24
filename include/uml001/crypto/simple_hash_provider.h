#pragma once
#include "uml001/crypto/hash_provider.h"
#include "uml001/crypto/crypto_utils.h"

namespace uml001 {
namespace crypto {

    class SimpleHashProvider : public IHashProvider {
    public:
        static SimpleHashProvider& instance() {
            static SimpleHashProvider inst;
            return inst;
        }

        std::string sha256(const std::string& input) override {
            return ::uml001::sha256_hex(input);
        }

        std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& input) override {
            return ::uml001::sha256_raw(input);
        }

        std::string sha512(const std::string& input) override {
            // Note: Add sha512_hex to crypto_utils if missing, or implement here using OpenSSL
            return ""; // Placeholder until sha512 is confirmed in crypto_utils
        }

        std::string sha3_256(const std::string& input) override {
             // Note: Add sha3_256_hex to crypto_utils if missing
            return ""; 
        }

    private:
        SimpleHashProvider() = default;
        ~SimpleHashProvider() override = default;
        SimpleHashProvider(const SimpleHashProvider&) = delete;
        SimpleHashProvider& operator=(const SimpleHashProvider&) = delete;
    };

} // namespace crypto
} // namespace uml001