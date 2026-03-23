<<<<<<< HEAD

/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/crypto/crypto_utils.h"
#include <vector>
#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

namespace uml001 {

// ---------------- HEX ----------------
static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// ---------------- SHA256 ----------------
std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP ctx allocation failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP digest update failed");
    }

    std::vector<uint8_t> digest(EVP_MD_size(EVP_sha256()));
    unsigned int len = 0;

    EVP_DigestFinal_ex(ctx, digest.data(), &len);
    EVP_MD_CTX_free(ctx);

    digest.resize(len);
    return digest;
}

std::string sha256_hex(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    // Use the modern "Envelope" API for OpenSSL 3.0+
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) &&
       EVP_DigestUpdate(context, input.c_str(), input.size()) &&
       EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(context);
        std::stringstream ss;
        for(unsigned int i = 0; i < lengthOfHash; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }
    if(context) EVP_MD_CTX_free(context);
    return ""; // Return empty string on failure
}

// ---------------- RANDOM ----------------
std::vector<uint8_t> secure_random_bytes(std::size_t length) {
    std::vector<uint8_t> out(length);
    if (RAND_bytes(out.data(), static_cast<int>(length)) != 1)
        throw std::runtime_error("OpenSSL RAND_bytes failed");
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

    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    (void)BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& input) {
    BIO *bio, *b64;
    std::vector<uint8_t> buffer(input.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int len = BIO_read(bio, buffer.data(), static_cast<int>(input.size()));
    BIO_free_all(bio);

    if (len < 0) return {};
    buffer.resize(static_cast<std::size_t>(len));
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
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) &&
              (EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& priv,
                                  const std::vector<uint8_t>& msg) {

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, priv.data(), priv.size());
    if (!pkey) throw std::runtime_error("PKEY raw key creation failed");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t siglen = 64;
    std::vector<uint8_t> sig(siglen);

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1 ||
        EVP_DigestSign(ctx, sig.data(), &siglen, msg.data(), msg.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP sign failed");
    }

    sig.resize(siglen);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return sig;
=======
#include "uml001/crypto/crypto_utils.h"
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <vector>

namespace uml001 {

std::string sha256_hex(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    // Use the modern "Envelope" API for OpenSSL 3.0+
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    
    if(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) &&
       EVP_DigestUpdate(context, input.c_str(), input.size()) &&
       EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
        
        EVP_MD_CTX_free(context);
        
        std::stringstream ss;
        for(unsigned int i = 0; i < lengthOfHash; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    if(context) EVP_MD_CTX_free(context);
    return ""; // Return empty string on failure
>>>>>>> bf3432f (feat(integration): fix sidecar config and modernize OpenSSL to EVP API)
}

} // namespace uml001