/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * The Aegis Protocol defines a distributed trust and identity framework
 * based on cryptographically verifiable Semantic Passports, capability
 * enforcement, and transparency logging for auditable system behavior.
 *
 * Core components include:
 *   - Semantic Passports: verifiable identity and capability attestations
 *   - Transparency Log: append-only cryptographic audit trail of system events
 *   - Revocation System: deterministic invalidation of compromised or expired identities
 *   - Passport Registry: issuance and verification authority for trusted entities
 *
 * This framework is designed for open standardization, interoperability,
 * and production-grade use in distributed identity, AI systems, and
 * verifiable authorization infrastructures.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for research, verifiable systems design,
 * and deployment in security-critical distributed environments.
 */
#include "uml001/crypto/crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>

namespace uml001 {

// Implementation of sha256_raw for internal byte-level hashing
std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    
    if(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) &&
       EVP_DigestUpdate(context, data.data(), data.size()) &&
       EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(context);
        return std::vector<uint8_t>(hash, hash + lengthOfHash);
    }

    if(context) EVP_MD_CTX_free(context);
    return {};
}

std::string sha256_hex(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
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
    return "";
}

// hex_encode for registry logging
std::string hex_encode(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t byte : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

// hex_decode required by PassportRegistry::verify
std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    std::vector<uint8_t> decoded(encoded.size() / 4 * 3 + 16);
    int length = BIO_read(bio, decoded.data(), decoded.size());
    BIO_free_all(bio);
    
    if (length < 0) return {};
    decoded.resize(length);
    return decoded;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    BIO_write(bio, data.data(), (int)data.size());
    BIO_flush(bio);
    
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return result;
}

std::string generate_random_bytes_hex(size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    if (RAND_bytes(buffer.data(), (int)bytes) != 1) return "";
    
    std::stringstream ss;
    for (unsigned char byte : buffer) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

std::vector<uint8_t> secure_random_bytes(size_t bytes) {
    std::vector<uint8_t> buffer(bytes);
    if (RAND_bytes(buffer.data(), (int)bytes) != 1) return {};
    return buffer;
}

bool ed25519_verify(const std::vector<uint8_t>& pubkey,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& signature) {
    if (pubkey.size() != 32 || signature.size() != 64) return false;
    
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());
    if (!pkey) return false;
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    int ret = EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey);
    if (ret > 0) {
        ret = EVP_DigestVerify(mdctx, signature.data(), signature.size(), message.data(), message.size());
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ret == 1;
}

std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& message) {
    if (private_key.size() != 32) return {};
    
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) return {};
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    size_t sig_len = 64;
    std::vector<uint8_t> signature(sig_len);
    
    int ret = EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey);
    if (ret > 0) {
        ret = EVP_DigestSign(mdctx, signature.data(), &sig_len, message.data(), message.size());
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    if (ret <= 0) return {};
    signature.resize(sig_len);
    return signature;
}

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t lengthOfHash = 0;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!ctx || 
        EVP_MAC_init(ctx, (const unsigned char*)key.c_str(), key.size(), params) != 1 ||
        EVP_MAC_update(ctx, (const unsigned char*)data.c_str(), data.size()) != 1 ||
        EVP_MAC_final(ctx, hash, &lengthOfHash, sizeof(hash)) != 1) {
        if (ctx) EVP_MAC_CTX_free(ctx);
        if (mac) EVP_MAC_free(mac);
        return "";
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    std::stringstream ss;
    for (size_t i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Overload to match KeyManager's usage of std::vector
void secure_zero(std::vector<uint8_t>& buffer) {
    if (!buffer.empty()) {
        OPENSSL_cleanse(buffer.data(), buffer.size());
    }
}

// AEAD Implementation (Preserved per previous logic)
EncryptionResult aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& plaintext,
                                    const std::vector<uint8_t>& aad) {
    EncryptionResult result;
    if (key.size() != 32) return result;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    result.nonce.resize(12);
    RAND_bytes(result.nonce.data(), 12);
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), result.nonce.data());
    if (!aad.empty()) EVP_EncryptUpdate(ctx, nullptr, nullptr, aad.data(), (int)aad.size());
    
    result.ciphertext.resize(plaintext.size());
    int len = 0;
    EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), (int)plaintext.size());
    
    result.tag.resize(16);
    EVP_EncryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data());
    
    EVP_CIPHER_CTX_free(ctx);
    result.ok = true;
    return result;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& tag,
                                        const std::vector<uint8_t>& aad) {
    if (key.size() != 32 || nonce.size() != 12 || tag.size() != 16) return {};
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> result(ciphertext.size());
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data());
    if (!aad.empty()) EVP_DecryptUpdate(ctx, nullptr, nullptr, aad.data(), (int)aad.size());
    
    if (EVP_DecryptUpdate(ctx, result.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

EncryptionResult chacha20_poly1305_encrypt(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& aad) {
    EncryptionResult result;
    if (key.size() != 32) return result;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    result.nonce.resize(12);
    RAND_bytes(result.nonce.data(), 12);
    
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), result.nonce.data());
    if (!aad.empty()) EVP_EncryptUpdate(ctx, nullptr, nullptr, aad.data(), (int)aad.size());
    
    result.ciphertext.resize(plaintext.size());
    int len = 0;
    EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), (int)plaintext.size());
    
    result.tag.resize(16);
    EVP_EncryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, result.tag.data());
    
    EVP_CIPHER_CTX_free(ctx);
    result.ok = true;
    return result;
}

std::vector<uint8_t> chacha20_poly1305_decrypt(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& ciphertext,
                                               const std::vector<uint8_t>& nonce,
                                               const std::vector<uint8_t>& tag,
                                               const std::vector<uint8_t>& aad) {
    if (key.size() != 32 || nonce.size() != 12 || tag.size() != 16) return {};
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> result(ciphertext.size());
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag.data());
    if (!aad.empty()) EVP_DecryptUpdate(ctx, nullptr, nullptr, aad.data(), (int)aad.size());
    
    if (EVP_DecryptUpdate(ctx, result.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

} // namespace uml001