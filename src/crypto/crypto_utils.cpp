#include "uml001/crypto/crypto_utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace uml001 {

// ---------------- HEX ----------------
static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

// ---------------- SHA256 ----------------
std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP ctx failed");

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());

    std::vector<uint8_t> digest(32);
    unsigned int len = 0;

    EVP_DigestFinal_ex(ctx, digest.data(), &len);
    EVP_MD_CTX_free(ctx);

    digest.resize(len);
    return digest;
}

std::string sha256_hex(const std::string& input) {
    return bytes_to_hex({sha256_raw({input.begin(), input.end()})});
}

// ---------------- RANDOM ----------------
std::vector<uint8_t> secure_random_bytes(std::size_t length) {
    std::vector<uint8_t> out(length);
    if (RAND_bytes(out.data(), length) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return out;
}

std::string generate_random_bytes_hex(std::size_t n) {
    return bytes_to_hex(secure_random_bytes(n));
}

// ---------------- BASE64 ----------------
std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& input) {
    BIO *bio, *b64;
    std::vector<uint8_t> buffer(input.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), input.size());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int len = BIO_read(bio, buffer.data(), input.size());
    BIO_free_all(bio);

    if (len < 0) return {};
    buffer.resize(len);
    return buffer;
}

// ---------------- CONST TIME ----------------
bool constant_time_equals(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// ---------------- ZERO ----------------
void secure_zero(std::vector<uint8_t>& buffer) {
    if (!buffer.empty())
        OPENSSL_cleanse(buffer.data(), buffer.size());
}

// ---------------- ED25519 ----------------
bool ed25519_verify(const std::vector<uint8_t>& pub,
                    const std::vector<uint8_t>& msg,
                    const std::vector<uint8_t>& sig) {

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    bool ok =
        EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
        EVP_DigestVerify(ctx, sig.data(), sig.size(),
                         msg.data(), msg.size()) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok;
}

std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& priv,
                                  const std::vector<uint8_t>& msg) {

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, priv.data(), priv.size());

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    size_t siglen = 64;
    std::vector<uint8_t> sig(siglen);

    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey);
    EVP_DigestSign(ctx, sig.data(), &siglen,
                   msg.data(), msg.size());

    sig.resize(siglen);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return sig;
}

} // namespace uml001