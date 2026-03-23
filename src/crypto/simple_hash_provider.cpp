#include "uml001/simple_hash_provider.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace uml001 {

static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

static std::vector<uint8_t> hash(const std::vector<uint8_t>& data, const EVP_MD* md) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestInit failed");
    }
    if (!data.empty() && EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestUpdate failed");
    }

    unsigned int len = EVP_MD_size(md);
    std::vector<uint8_t> digest(len);
    if (EVP_DigestFinal_ex(ctx, digest.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestFinal failed");
    }

    EVP_MD_CTX_free(ctx);
    digest.resize(len);
    return digest;
}

// ================= SHA-256 =================
std::string SimpleHashProvider::sha256(const std::string& input) {
    auto digest = hash({input.begin(), input.end()}, EVP_sha256());
    return bytes_to_hex(digest);
}

std::vector<uint8_t> SimpleHashProvider::sha256_raw(const std::vector<uint8_t>& data) {
    return hash(data, EVP_sha256());
}

// ================= SHA-512 =================
std::string SimpleHashProvider::sha512(const std::string& input) {
    auto digest = hash({input.begin(), input.end()}, EVP_sha512());
    return bytes_to_hex(digest);
}

std::vector<uint8_t> SimpleHashProvider::sha512_raw(const std::vector<uint8_t>& data) {
    return hash(data, EVP_sha512());
}

// ================= SHA3-256 =================
std::string SimpleHashProvider::sha3_256(const std::string& input) {
    auto digest = hash({input.begin(), input.end()}, EVP_sha3_256());
    return bytes_to_hex(digest);
}

std::vector<uint8_t> SimpleHashProvider::sha3_256_raw(const std::vector<uint8_t>& data) {
    return hash(data, EVP_sha3_256());
}

// ================= SHA3-512 =================
std::string SimpleHashProvider::sha3_512(const std::string& input) {
    auto digest = hash({input.begin(), input.end()}, EVP_sha3_512());
    return bytes_to_hex(digest);
}

std::vector<uint8_t> SimpleHashProvider::sha3_512_raw(const std::vector<uint8_t>& data) {
    return hash(data, EVP_sha3_512());
}

} // namespace uml001