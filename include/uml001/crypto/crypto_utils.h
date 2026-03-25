#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace uml001 {

/**
 * @brief Compute SHA-256 hash of input string and return as hex string.
 * @param input The string to hash
 * @return Hexadecimal representation of the hash (lowercase)
 */
std::string sha256_hex(const std::string& input);

/**
 * @brief Decode base64-encoded string to raw bytes.
 * @param encoded The base64-encoded string
 * @return Vector of decoded bytes
 */
std::vector<uint8_t> base64_decode(const std::string& encoded);

/**
 * @brief Encode raw bytes to base64 string.
 * @param data The raw bytes to encode
 * @return Base64-encoded string
 */
std::string base64_encode(const std::vector<uint8_t>& data);

/**
 * @brief Generate cryptographically secure random bytes and return as hex string.
 * @param bytes Number of random bytes to generate
 * @return Hexadecimal representation of random bytes
 */
std::string generate_random_bytes_hex(size_t bytes);

/**
 * @brief Generate cryptographically secure random bytes.
 * @param bytes Number of random bytes to generate
 * @return Vector of random bytes
 */
std::vector<uint8_t> secure_random_bytes(size_t bytes);

/**
 * @brief Verify an Ed25519 signature.
 * @param pubkey The public key (32 bytes)
 * @param message The message that was signed
 * @param signature The signature to verify (64 bytes)
 * @return true if signature is valid, false otherwise
 */
bool ed25519_verify(const std::vector<uint8_t>& pubkey,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& signature);

/**
 * @brief Sign a message with Ed25519.
 * @param private_key The private key (32 bytes)
 * @param message The message to sign
 * @return The signature (64 bytes)
 */
std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& message);

/**
 * @brief Compute HMAC-SHA256 hash and return as hex string.
 * @param key The HMAC key
 * @param data The data to authenticate
 * @return Hexadecimal representation of the HMAC (lowercase)
 */
std::string hmac_sha256_hex(const std::string& key, const std::string& data);

/**
 * @brief Securely zero out memory to prevent sensitive data leakage.
 * @param ptr Pointer to memory to zero
 * @param size Number of bytes to zero
 */
void secure_zero(void* ptr, size_t size);

// Encryption/Decryption structures and functions
struct EncryptionResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;
    bool ok = false;
};

/**
 * @brief Encrypt data using AES-256-GCM.
 * @param key 32-byte AES key
 * @param plaintext Data to encrypt
 * @param aad Additional authenticated data (optional)
 * @return EncryptionResult with ciphertext, nonce, and auth tag
 */
EncryptionResult aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& plaintext,
                                    const std::vector<uint8_t>& aad = {});

/**
 * @brief Decrypt data using AES-256-GCM.
 * @param key 32-byte AES key
 * @param ciphertext Encrypted data
 * @param nonce Nonce used during encryption
 * @param tag Authentication tag
 * @param aad Additional authenticated data (must match encryption call)
 * @return Decrypted plaintext, or empty vector on failure
 */
std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& tag,
                                        const std::vector<uint8_t>& aad = {});

/**
 * @brief Encrypt data using ChaCha20-Poly1305.
 * @param key 32-byte key
 * @param plaintext Data to encrypt
 * @param aad Additional authenticated data (optional)
 * @return EncryptionResult with ciphertext, nonce, and auth tag
 */
EncryptionResult chacha20_poly1305_encrypt(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& aad = {});

/**
 * @brief Decrypt data using ChaCha20-Poly1305.
 * @param key 32-byte key
 * @param ciphertext Encrypted data
 * @param nonce Nonce used during encryption (12 bytes)
 * @param tag Authentication tag (16 bytes)
 * @param aad Additional authenticated data (must match encryption call)
 * @return Decrypted plaintext, or empty vector on failure
 */
std::vector<uint8_t> chacha20_poly1305_decrypt(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& ciphertext,
                                               const std::vector<uint8_t>& nonce,
                                               const std::vector<uint8_t>& tag,
                                               const std::vector<uint8_t>& aad = {});

} // namespace uml001
