#include "uml001/crypto/hash_provider.h"
#include <vector>
#include <string>

namespace uml001 {
namespace crypto {

// ============================================================
// HSMHashProvider placeholders
// ============================================================

std::string HSMHashProvider::sha256(const std::string& data) {
    return "HSM_SHA256_PLACEHOLDER";
}

std::vector<uint8_t> HSMHashProvider::sha256_raw(const std::vector<uint8_t>& input) {
    return std::vector<uint8_t>(32, 0x00);
}

std::string HSMHashProvider::sha512(const std::string& input) {
    return "HSM_SHA512_PLACEHOLDER";
}

std::string HSMHashProvider::sha3_256(const std::string& input) {
    return "HSM_SHA3_256_PLACEHOLDER";
}

} // namespace crypto
} // namespace uml001