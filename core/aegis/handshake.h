// handshake.h  (UML-001 rev 1.3 - Patched for Nonce Partitioning)
#pragma once
#include "passport.h"
#include <string>
#include <unordered_set>
#include <stdexcept>
#include <random>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <algorithm>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

namespace uml001 {

// =============================================================================
// SECTION 1: UTILITIES & PRIMITIVES
// =============================================================================

inline std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

inline std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), (int)key.size(),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash, &len);
    std::ostringstream oss;
    for (unsigned int i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::invalid_argument("Odd hex length");
    std::vector<uint8_t> out;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        out.push_back(byte);
    }
    return out;
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (auto b : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

inline std::vector<uint8_t> hkdf_sha256(const std::string& ikm, const std::string& salt, 
                                        const std::string& info, size_t out_len = 32) {
    std::vector<uint8_t> out(out_len);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());
    params[2] = OSSL_PARAM_construct_octet_string("salt", (void*)salt.data(), salt.size());
    params[3] = OSSL_PARAM_construct_octet_string("info", (void*)info.data(), info.size());
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out.data(), out_len, params) <= 0) 
        throw std::runtime_error("HKDF failed");
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return out;
}

inline std::string generate_nonce(size_t bytes = 32) {
    std::vector<uint8_t> buf(bytes);
    if (RAND_bytes(buf.data(), (int)bytes) != 1) throw std::runtime_error("CSPRNG failure");
    return bytes_to_hex(buf);
}

// =============================================================================
// SECTION 2: NONCE NAMESPACE PARTITIONING
// =============================================================================

enum class NonceRole { INITIATOR, RESPONDER };

class NonceCache {
public:
    // Partitioning Fix: Prefix nonces based on role to prevent reflection.
    bool consume(NonceRole role, const std::string& nonce) {
        std::string partitioned_nonce = (role == NonceRole::INITIATOR ? "I:" : "R:") + nonce;
        auto [it, inserted] = seen_.insert(partitioned_nonce);
        return inserted; 
    }
private:
    std::unordered_set<std::string> seen_;
};

// =============================================================================
// SECTION 3: EPHEMERAL KEYS & TRANSPORT
// =============================================================================

struct EphemeralKeyPair {
    std::string private_hex;
    std::string public_hex;

    std::string derive_shared_secret(const std::string& peer_public_hex,
                                     const std::string& initiator_nonce,
                                     const std::string& responder_nonce) const {
        auto local_priv = hex_to_bytes(private_hex);
        auto peer_pub   = hex_to_bytes(peer_public_hex);
        std::vector<uint8_t> ikm(local_priv.size());
        for (size_t i = 0; i < ikm.size(); ++i) ikm[i] = local_priv[i] ^ peer_pub[i];

        // Context-aware salt includes both nonces in a fixed order
        std::string salt = "I:" + initiator_nonce + "|R:" + responder_nonce;
        auto key_bytes = hkdf_sha256(std::string(ikm.begin(), ikm.end()), salt, "uml001-dh-v1", 32);
        return bytes_to_hex(key_bytes);
    }

    void destroy_private_key() {
        std::fill(private_hex.begin(), private_hex.end(), '\0');
        private_hex.clear();
    }
};

inline EphemeralKeyPair generate_ephemeral_keypair() {
    EphemeralKeyPair kp;
    kp.private_hex = generate_nonce(32);
    auto pub_bytes = hkdf_sha256(std::string(hex_to_bytes(kp.private_hex).begin(), 
                                 hex_to_bytes(kp.private_hex).end()), 
                                 "static-salt", "uml001-pub-v1", 32);
    kp.public_hex = bytes_to_hex(pub_bytes);
    return kp;
}

enum class TransportBindingType { TLS_CERT_FINGERPRINT, TCP_ADDRESS, NONE };
struct TransportIdentity {
    TransportBindingType type = TransportBindingType::NONE;
    std::string value;
    std::string binding_token() const {
        return (type == TransportBindingType::TLS_CERT_FINGERPRINT ? "tls:" : "tcp:") + value;
    }
    bool is_strong() const { return type == TransportBindingType::TLS_CERT_FINGERPRINT; }
};

// =============================================================================
// SECTION 4: HANDSHAKE MESSAGES & LOGIC
// =============================================================================

struct HelloMessage {
    SemanticPassport passport;
    std::string      session_nonce;
    std::string      proposed_schema;
    std::string      ephemeral_public_hex;
    TransportIdentity transport;
};

struct HelloAckMessage {
    SemanticPassport passport;
    std::string      session_nonce;
    std::string      accepted_schema;
    std::string      session_id;
    std::string      ephemeral_public_hex;
    TransportIdentity transport;
};

struct HelloConfirmMessage {
    std::string session_id;
    std::string signature;
};

struct SessionContext {
    std::string session_id;
    std::string session_key_hex;
    bool        forward_secrecy = false;
};

class HandshakeValidator {
public:
    HandshakeValidator(const PassportRegistry& registry, const SemanticPassport& local_passport,
                       std::string schema, TransportIdentity transport, NonceCache& cache, uint64_t now)
        : registry_(registry), local_passport_(local_passport), local_schema_(schema),
          local_transport_(transport), nonce_cache_(cache), now_(now) {}

    // Process Message 1 (Responder)
    struct Result { bool accepted = false; HelloAckMessage ack; SessionContext session; std::string reason; };

    Result validate_hello(const HelloMessage& msg) {
        Result res;
        // Fix 1: Check peer nonce in INITIATOR namespace
        if (!nonce_cache_.consume(NonceRole::INITIATOR, msg.session_nonce)) {
            res.reason = "REPLAY_DETECTED"; return res;
        }

        if (!registry_.verify(msg.passport, now_).ok()) { res.reason = "INVALID_PASSPORT"; return res; }

        local_nonce_ = generate_nonce();
        local_ephemeral_ = generate_ephemeral_keypair();

        // Fix 2: Session ID material is now strictly ordered by role
        std::string sid_material = "INIT_NONCE:" + msg.session_nonce + 
                                   "|RESP_NONCE:" + local_nonce_ +
                                   "|INIT_TRANS:" + msg.transport.binding_token() +
                                   "|RESP_TRANS:" + local_transport_.binding_token();
        res.ack.session_id = sha256_hex(sid_material);

        std::string secret = local_ephemeral_.derive_shared_secret(msg.ephemeral_public_hex, 
                                                                  msg.session_nonce, local_nonce_);
        
        auto key = hkdf_sha256(std::string(hex_to_bytes(secret).begin(), hex_to_bytes(secret).end()),
                               res.ack.session_id, "uml001-session-v1", 32);

        pending_session_.session_key_hex = bytes_to_hex(key);
        pending_session_.session_id = res.ack.session_id;
        
        local_ephemeral_.destroy_private_key(); // Forward Secrecy

        res.ack.passport = local_passport_;
        res.ack.session_nonce = local_nonce_;
        res.ack.ephemeral_public_hex = local_ephemeral_.public_hex;
        res.ack.transport = local_transport_;
        res.accepted = true;
        return res;
    }

    // Initiator side logic
    HelloMessage build_hello() {
        local_nonce_ = generate_nonce();
        local_ephemeral_ = generate_ephemeral_keypair();
        return { local_passport_, local_nonce_, local_schema_, local_ephemeral_.public_hex, local_transport_ };
    }

    struct AckResult { bool accepted = false; HelloConfirmMessage confirm; SessionContext session; std::string reason; };
    
    AckResult process_ack(const HelloAckMessage& ack) {
        AckResult res;
        // Fix 3: Check peer nonce in RESPONDER namespace
        if (!nonce_cache_.consume(NonceRole::RESPONDER, ack.session_nonce)) {
            res.reason = "REPLAY_DETECTED"; return res;
        }

        std::string sid_material = "INIT_NONCE:" + local_nonce_ + 
                                   "|RESP_NONCE:" + ack.session_nonce +
                                   "|INIT_TRANS:" + local_transport_.binding_token() +
                                   "|RESP_TRANS:" + ack.transport.binding_token();
        std::string sid = sha256_hex(sid_material);
        if (sid != ack.session_id) { res.reason = "SID_MISMATCH"; return res; }

        std::string secret = local_ephemeral_.derive_shared_secret(ack.ephemeral_public_hex, 
                                                                  local_nonce_, ack.session_nonce);
        
        auto key_bytes = hkdf_sha256(std::string(hex_to_bytes(secret).begin(), hex_to_bytes(secret).end()),
                                     sid, "uml001-session-v1", 32);

        res.session.session_id = sid;
        res.session.session_key_hex = bytes_to_hex(key_bytes);
        res.session.forward_secrecy = true;
        
        local_ephemeral_.destroy_private_key();

        res.confirm.session_id = sid;
        res.confirm.signature = hmac_sha256_hex(std::string(key_bytes.begin(), key_bytes.end()), sid);
        res.accepted = true;
        return res;
    }

private:
    const PassportRegistry& registry_;
    const SemanticPassport& local_passport_;
    std::string local_schema_;
    TransportIdentity local_transport_;
    NonceCache& nonce_cache_;
    uint64_t now_;
    std::string local_nonce_;
    EphemeralKeyPair local_ephemeral_;
    SessionContext pending_session_;
};

} // namespace uml001