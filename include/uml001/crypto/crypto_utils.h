#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace uml001 {

// SHA-256
std::string sha256_hex(const std::string& input);
std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data);

// Random
std::vector<uint8_t> secure_random_bytes(std::size_t length);
std::string generate_random_bytes_hex(std::size_t num_bytes);

// Base64
std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& input);

// Constant-time
bool constant_time_equals(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b);

// Secure memory wipe
void secure_zero(std::vector<uint8_t>& buffer);

// Ed25519
std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& message);

bool ed25519_verify(const std::vector<uint8_t>& public_key,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& signature);

} // namespace uml001