<<<<<<< HEAD
<<<<<<< HEAD

=======
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
<<<<<<< HEAD
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
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>

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
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    std::vector<uint8_t> decoded(encoded.size() / 4 * 3 + 16);
    int length = BIO_read(bio, decoded.data(), decoded.size());
    
    BIO_free_all(bio);
    
    if (length < 0) {
        return std::vector<uint8_t>();
    }
    
    decoded.resize(length);
    return decoded;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    
    return result;
}

std::string generate_random_bytes_hex(size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    
    if (RAND_bytes(buffer.data(), bytes) != 1) {
        return ""; // Error case
    }
    
    std::stringstream ss;
    for (unsigned char byte : buffer) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    
    return ss.str();
}

std::vector<uint8_t> secure_random_bytes(size_t bytes) {
    std::vector<uint8_t> buffer(bytes);
    
    if (RAND_bytes(buffer.data(), bytes) != 1) {
        return std::vector<uint8_t>(); // Error case
    }
    
    return buffer;
}

bool ed25519_verify(const std::vector<uint8_t>& pubkey,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& signature) {
    // Ed25519 requires exactly 32-byte public key and 64-byte signature
    if (pubkey.size() != 32 || signature.size() != 64) {
        return false;
    }
    
    // Use OpenSSL's Ed25519 verification via EVP_PKEY
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());
    if (!pkey) {
        return false;
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    
    int ret = EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey);
    if (ret <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    ret = EVP_DigestVerifyUpdate(mdctx, message.data(), message.size());
    if (ret <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    return ret == 1;
}

std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& message) {
    // Ed25519 requires exactly 32-byte private key
    if (private_key.size() != 32) {
        return std::vector<uint8_t>();
    }
    
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) {
        return std::vector<uint8_t>();
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return std::vector<uint8_t>();
    }
    
    int ret = EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey);
    if (ret <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> signature(64);
    size_t sig_len = signature.size();
    
    ret = EVP_DigestSignFinal(mdctx, signature.data(), &sig_len);
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    if (ret <= 0) {
        return std::vector<uint8_t>();
    }
    
    signature.resize(sig_len);
    return signature;
}

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    
    HMAC_CTX* hmac = HMAC_CTX_new();
    
    if(!HMAC_Init_ex(hmac, key.c_str(), key.size(), EVP_sha256(), nullptr) ||
       !HMAC_Update(hmac, (unsigned char*)data.c_str(), data.size()) ||
       !HMAC_Final(hmac, hash, &lengthOfHash)) {
        
        HMAC_CTX_free(hmac);
        return "";
    }
    
    HMAC_CTX_free(hmac);
    
    std::stringstream ss;
    for(unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}

void secure_zero(void* ptr, size_t size) {
    // Use OpenSSL's secure memory zeroing function
    OPENSSL_cleanse(ptr, size);
}

EncryptionResult aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& plaintext,
                                    const std::vector<uint8_t>& aad) {
    EncryptionResult result;
    
    if (key.size() != 32) {
        return result; // AES-256 requires 32-byte key
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;
    
    // Generate random 12-byte nonce
    result.nonce.resize(12);
    if (RAND_bytes(result.nonce.data(), 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), result.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set AAD if provided
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, nullptr, aad.data(), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }
    
    // Encrypt plaintext
    result.ciphertext.resize(plaintext.size() + 16); // Extra space for ciphertext
    int len = 0;
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    result.ciphertext.resize(len);
    
    // Finalize and get tag
    result.tag.resize(16);
    if (EVP_EncryptFinal_ex(ctx, nullptr, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    result.ok = true;
    return result;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& tag,
                                        const std::vector<uint8_t>& aad) {
    std::vector<uint8_t> result;
    
    if (key.size() != 32 || nonce.size() != 12 || tag.size() != 16) {
        return result; // Invalid sizes
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set tag for authentication
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set AAD if provided
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, nullptr, aad.data(), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }
    
    // Decrypt ciphertext
    result.resize(ciphertext.size());
    int len = 0;
    if (EVP_DecryptUpdate(ctx, result.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>(); // Authentication failed
    }
    result.resize(len);
    
    // Finalize and verify tag
    if (EVP_DecryptFinal_ex(ctx, nullptr, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>(); // Authentication failed
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

EncryptionResult chacha20_poly1305_encrypt(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& aad) {
    EncryptionResult result;
    
    if (key.size() != 32) {
        return result; // ChaCha20 requires 32-byte key
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;
    
    // Generate random 12-byte nonce
    result.nonce.resize(12);
    if (RAND_bytes(result.nonce.data(), 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), result.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set AAD if provided
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, nullptr, aad.data(), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }
    
    // Encrypt plaintext
    result.ciphertext.resize(plaintext.size() + 16);
    int len = 0;
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    result.ciphertext.resize(len);
    
    // Finalize and get tag
    result.tag.resize(16);
    if (EVP_EncryptFinal_ex(ctx, nullptr, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    result.ok = true;
    return result;
}

std::vector<uint8_t> chacha20_poly1305_decrypt(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& ciphertext,
                                               const std::vector<uint8_t>& nonce,
                                               const std::vector<uint8_t>& tag,
                                               const std::vector<uint8_t>& aad) {
    std::vector<uint8_t> result;
    
    if (key.size() != 32 || nonce.size() != 12 || tag.size() != 16) {
        return result; // Invalid sizes
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set tag for authentication
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, (void*)tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set AAD if provided
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, nullptr, aad.data(), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }
    
    // Decrypt ciphertext
    result.resize(ciphertext.size());
    int len = 0;
    if (EVP_DecryptUpdate(ctx, result.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    result.resize(len);
    
    // Finalize and verify tag
    if (EVP_DecryptFinal_ex(ctx, nullptr, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

} // namespace uml001