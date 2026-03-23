#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace uml001 {
namespace crypto {

    struct Envelope {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> tag; // Empty for CTR mode
    };

    // --- AEAD Encryption (GCM & ChaCha20) ---
    Envelope encrypt_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {});
    std::vector<uint8_t> decrypt_gcm(const std::vector<uint8_t>& key, const Envelope& env, const std::vector<uint8_t>& aad = {});

    Envelope encrypt_chacha20(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {});
    std::vector<uint8_t> decrypt_chacha20(const std::vector<uint8_t>& key, const Envelope& env, const std::vector<uint8_t>& aad = {});

    // --- Ed25519 Signatures ---
    std::vector<uint8_t> sign_payload(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& payload);
    bool verify_signature(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& payload);

    // --- Utilities ---
    std::string to_base64(const std::vector<uint8_t>& data);
    std::vector<uint8_t> from_base64(const std::string& data);

} // namespace crypto
} // namespace uml001