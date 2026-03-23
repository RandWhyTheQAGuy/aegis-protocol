#include "uml001/hash_provider.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <stdexcept>

namespace uml001 {

// ============================================================
// Utility: bytes → hex
// ============================================================
static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// ============================================================
// SimpleHashProvider (singleton)
// ============================================================
SimpleHashProvider& SimpleHashProvider::instance() {
    static SimpleHashProvider provider;
    return provider;
}

std::vector<uint8_t> SimpleHashProvider::sha256_raw(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(input.data(), input.size(), hash.data())) {
        throw std::runtime_error("SHA256 computation failed");
    }
    return hash;
}

std::string SimpleHashProvider::sha256(const std::string& input) {
    std::vector<uint8_t> raw(input.begin(), input.end());
    return bytes_to_hex(sha256_raw(raw));
}

std::string SimpleHashProvider::sha512(const std::string& input) {
    std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);
    if (!SHA512(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash.data())) {
        throw std::runtime_error("SHA512 computation failed");
    }
    return bytes_to_hex(hash);
}

std::string SimpleHashProvider::sha3_256(const std::string& input) {
    std::vector<uint8_t> hash(32); // SHA3-256 output
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA3-256 computation failed");
    }
    EVP_MD_CTX_free(ctx);
    return bytes_to_hex(hash);
}

// ============================================================
// HSMHashProvider placeholders
// ============================================================

std::string HSMHashProvider::sha256(const std::string& data) {
    // Placeholder; integrate with PKCS#11/CryptoAPI
    return "HSM_SHA256_PLACEHOLDER";
}

std::vector<uint8_t> HSMHashProvider::sha256_raw(const std::vector<uint8_t>& input) {
    // Placeholder raw bytes
    return std::vector<uint8_t>(32, 0x00);
}

std::string HSMHashProvider::sha512(const std::string& input) {
    return "HSM_SHA512_PLACEHOLDER";
}

std::string HSMHashProvider::sha3_256(const std::string& input) {
    return "HSM_SHA3_256_PLACEHOLDER";
}

} // namespace uml001