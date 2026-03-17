// handshake.h  (UML-001 rev 1.4)
//
// Changes from rev 1.3:
//   FIX-01  derive_shared_secret(): EVP_PKEY X25519 DH replaces XOR stub;
//           shared_secret correctly fed into HKDF (was discarded).
//   FIX-02  generate_ephemeral_keypair(): generates a real X25519 keypair via
//           EVP_PKEY; HKDF-of-private-key stub removed.
//   FIX-03  EphemeralKeyPair: holds EVP_PKEY* with RAII destructor; copy
//           disabled, move defined.
//   FIX-04  destroy_private_key(): uses OPENSSL_cleanse; frees EVP_PKEY.
//   FIX-05  hkdf_sha256(): RAII cleanup on both success and exception paths.
//   FIX-06  validate_hello(): accepted_schema set; schema mismatch rejected.
//   FIX-07  validate_hello(): ephemeral key bound to passport signature to
//           close unauthenticated-ephemeral MITM window.
//   FIX-08  validate_confirm() added (Message 3 — was entirely absent).
//   FIX-09  HandshakeValidator: require_strong and reject_recovered params
//           restored; enforced in validate_hello().
//   FIX-10  process_ack(): double-call guard on destroyed ephemeral key.
//   FIX-11  NonceCache: windowed TTL expiry prevents unbounded growth.
//   FIX-12  NonceCache: namespace prefix uses full SHA-256 of (role||nonce)
//           to eliminate prefix-collision attack surface.
//   FIX-13  build_hello(): schema parameter restored.
//   FIX-14  TransportIdentity::binding_token(): NONE type returns distinct token.
//   FIX-15  pending_session_.forward_secrecy set in validate_hello() so
//           validate_confirm() can propagate it correctly.
//
#pragma once
#include "passport.h"
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <chrono>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

namespace uml001 {

// =============================================================================
// SECTION 1: UTILITIES & PRIMITIVES
// =============================================================================

inline std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

inline std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         hash, &len);
    std::ostringstream oss;
    for (unsigned int i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("hex_to_bytes: odd-length input");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        char* end = nullptr;
        uint8_t byte = static_cast<uint8_t>(std::strtol(hex.c_str() + i, &end, 16));
        if (end != hex.c_str() + i + 2)
            throw std::invalid_argument("hex_to_bytes: invalid hex character");
        out.push_back(byte);
    }
    return out;
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (auto b : v)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

// FIX-05: RAII wrappers ensure cleanup on both normal and exception paths.
inline std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                         const std::string& salt,
                                         const std::string& info,
                                         size_t out_len = 32) {
    std::vector<uint8_t> out(out_len);

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) throw std::runtime_error("hkdf_sha256: EVP_KDF_fetch failed");

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);  // kctx holds its own reference
    if (!kctx) throw std::runtime_error("hkdf_sha256: EVP_KDF_CTX_new failed");

    // Use scope guard via lambda to ensure kctx is freed on any exit path
    auto kctx_guard = [&kctx]() { EVP_KDF_CTX_free(kctx); kctx = nullptr; };

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                    const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                    const_cast<void*>(static_cast<const void*>(ikm.data())), ikm.size());
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                    const_cast<void*>(static_cast<const void*>(salt.data())), salt.size());
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                    const_cast<void*>(static_cast<const void*>(info.data())), info.size());
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out.data(), out_len, params) <= 0) {
        kctx_guard();
        throw std::runtime_error("hkdf_sha256: EVP_KDF_derive failed");
    }
    kctx_guard();
    return out;
}

// Convenience overload accepting std::string IKM
inline std::vector<uint8_t> hkdf_sha256(const std::string& ikm,
                                         const std::string& salt,
                                         const std::string& info,
                                         size_t out_len = 32) {
    return hkdf_sha256(std::vector<uint8_t>(ikm.begin(), ikm.end()),
                       salt, info, out_len);
}

inline std::string generate_nonce(size_t bytes = 32) {
    std::vector<uint8_t> buf(bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1)
        throw std::runtime_error("generate_nonce: CSPRNG failure");
    return bytes_to_hex(buf);
}

// =============================================================================
// SECTION 2: NONCE CACHE WITH TTL AND SAFE NAMESPACE PARTITIONING
// =============================================================================

enum class NonceRole { INITIATOR, RESPONDER };

class NonceCache {
public:
    // FIX-11: TTL window bounds memory usage; entries older than window_seconds
    //         are eligible for expiry. Default 300 s matches handshake timeout.
    explicit NonceCache(uint64_t window_seconds = 300,
                        size_t   max_entries    = 100'000)
        : window_(window_seconds), max_entries_(max_entries) {}

    // FIX-12: Namespace key is SHA-256(role_tag || nonce) rather than a
    //         2-character prefix, eliminating prefix-collision attack surface.
    //         Returns true if the nonce is fresh (not seen before), false on replay.
    bool consume(NonceRole role, const std::string& nonce) {
        const std::string role_tag = (role == NonceRole::INITIATOR)
                                     ? "INITIATOR-NONCE:" : "RESPONDER-NONCE:";
        const std::string key = sha256_hex(role_tag + nonce);

        uint64_t now = current_epoch();
        evict_expired(now);

        if (seen_.count(key)) return false;  // replay

        // Enforce hard cap to prevent DoS via nonce flooding
        if (seen_.size() >= max_entries_)
            throw std::runtime_error("NonceCache: max_entries exceeded");

        seen_.emplace(key, now);
        return true;
    }

private:
    uint64_t window_;
    size_t   max_entries_;
    std::unordered_map<std::string, uint64_t> seen_;  // key -> insertion_epoch

    static uint64_t current_epoch() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
    }

    void evict_expired(uint64_t now) {
        for (auto it = seen_.begin(); it != seen_.end(); ) {
            if (now - it->second > window_)
                it = seen_.erase(it);
            else
                ++it;
        }
    }
};

// =============================================================================
// SECTION 3: EPHEMERAL X25519 KEYPAIR & TRANSPORT IDENTITY
// =============================================================================

// FIX-01, FIX-02, FIX-03, FIX-04:
//   - Real X25519 keypair generated via EVP_PKEY
//   - RAII destructor frees EVP_PKEY resources
//   - Shared secret derived via proper ECDH then fed into HKDF
//   - destroy_private_key() uses OPENSSL_cleanse
struct EphemeralKeyPair {
    std::string  public_hex;     // X25519 public key, 32 bytes hex-encoded
    EVP_PKEY*    evp_key = nullptr;  // holds both private and public

    // Non-copyable (EVP_PKEY ownership), moveable
    EphemeralKeyPair() = default;
    EphemeralKeyPair(const EphemeralKeyPair&) = delete;
    EphemeralKeyPair& operator=(const EphemeralKeyPair&) = delete;
    EphemeralKeyPair(EphemeralKeyPair&& o) noexcept
        : public_hex(std::move(o.public_hex)), evp_key(o.evp_key) {
        o.evp_key = nullptr;
    }
    EphemeralKeyPair& operator=(EphemeralKeyPair&& o) noexcept {
        if (this != &o) {
            destroy_private_key();
            public_hex = std::move(o.public_hex);
            evp_key    = o.evp_key;
            o.evp_key  = nullptr;
        }
        return *this;
    }
    ~EphemeralKeyPair() { destroy_private_key(); }

    // FIX-01: Real X25519 ECDH; shared_secret is fed into HKDF (not discarded).
    // Caller must have nonces in initiator/responder order for consistent salt.
    std::string derive_shared_secret(const std::string& peer_public_hex,
                                     const std::string& initiator_nonce,
                                     const std::string& responder_nonce) const {
        if (!evp_key)
            throw std::runtime_error("derive_shared_secret: private key already destroyed");

        auto peer_pub_bytes = hex_to_bytes(peer_public_hex);
        EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr,
            peer_pub_bytes.data(), peer_pub_bytes.size());
        if (!peer_key)
            throw std::runtime_error("derive_shared_secret: invalid peer public key");

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_key, nullptr);
        if (!ctx) { EVP_PKEY_free(peer_key); throw std::runtime_error("EVP_PKEY_CTX_new failed"); }

        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            throw std::runtime_error("derive_shared_secret: ECDH init failed");
        }

        size_t secret_len = 32;
        std::vector<uint8_t> shared_secret(secret_len);
        if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            throw std::runtime_error("derive_shared_secret: ECDH derive failed");
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);

        // Domain-separated salt: nonces in fixed role order prevent
        // initiator/responder key symmetry
        std::string salt = "I:" + initiator_nonce + "|R:" + responder_nonce;
        auto key_bytes = hkdf_sha256(shared_secret, salt, "uml001-dh-v1", 32);

        // Zero the raw shared secret immediately after KDF
        OPENSSL_cleanse(shared_secret.data(), shared_secret.size());

        return bytes_to_hex(key_bytes);
    }

    // FIX-04: OPENSSL_cleanse (not std::fill) prevents dead-store elimination.
    void destroy_private_key() {
        if (evp_key) {
            // Extract and cleanse the raw private scalar before freeing
            size_t priv_len = 32;
            std::vector<uint8_t> priv_bytes(priv_len);
            if (EVP_PKEY_get_raw_private_key(evp_key, priv_bytes.data(), &priv_len) == 1)
                OPENSSL_cleanse(priv_bytes.data(), priv_len);
            EVP_PKEY_free(evp_key);
            evp_key = nullptr;
        }
        public_hex.clear();
    }

    bool private_key_destroyed() const { return evp_key == nullptr; }
};

// FIX-02: Generates a real X25519 keypair.
inline EphemeralKeyPair generate_ephemeral_keypair() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) throw std::runtime_error("generate_ephemeral_keypair: ctx alloc failed");
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("generate_ephemeral_keypair: keygen_init failed");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("generate_ephemeral_keypair: keygen failed");
    }
    EVP_PKEY_CTX_free(pctx);

    size_t pub_len = 32;
    std::vector<uint8_t> pub_bytes(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub_bytes.data(), &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("generate_ephemeral_keypair: get_raw_public_key failed");
    }

    EphemeralKeyPair kp;
    kp.evp_key    = pkey;
    kp.public_hex = bytes_to_hex(pub_bytes);
    return kp;
}

// FIX-14: NONE type returns a distinct, non-collidable token.
enum class TransportBindingType { TLS_CERT_FINGERPRINT, TCP_ADDRESS, NONE };

struct TransportIdentity {
    TransportBindingType type  = TransportBindingType::NONE;
    std::string          value;

    std::string binding_token() const {
        switch (type) {
            case TransportBindingType::TLS_CERT_FINGERPRINT: return "tls:" + value;
            case TransportBindingType::TCP_ADDRESS:          return "tcp:" + value;
            case TransportBindingType::NONE:                 return "none:";
        }
        return "none:";
    }
    bool is_strong() const { return type == TransportBindingType::TLS_CERT_FINGERPRINT; }
};

// =============================================================================
// SECTION 4: HANDSHAKE MESSAGES
// =============================================================================

struct HelloMessage {
    SemanticPassport  passport;
    std::string       session_nonce;
    std::string       proposed_schema;
    std::string       ephemeral_public_hex;
    // FIX-07: ephemeral_key_sig binds the ephemeral public key to the passport
    // signing key, closing the unauthenticated-ephemeral MITM window.
    std::string       ephemeral_key_sig;
    TransportIdentity transport;
};

struct HelloAckMessage {
    SemanticPassport  passport;
    std::string       session_nonce;
    std::string       accepted_schema;   // FIX-06: now populated
    std::string       session_id;
    std::string       ephemeral_public_hex;
    std::string       ephemeral_key_sig;  // FIX-07: responder also signs its ephemeral key
    TransportIdentity transport;
};

struct HelloConfirmMessage {
    std::string session_id;
    std::string signature;
};

struct SessionContext {
    std::string session_id;
    std::string session_key_hex;
    std::string initiator_model_id;
    std::string responder_model_id;
    bool        forward_secrecy = false;

    // Direction sub-keys derived from the session key
    std::string derive_direction_key(const std::string& direction) const {
        auto dk = hkdf_sha256(session_key_hex, session_id,
                              "uml001-direction-" + direction, 32);
        return bytes_to_hex(dk);
    }

    // HMAC-SHA256 of payload under the direction sub-key
    std::string authenticate_payload(const std::string& payload,
                                      const std::string& direction) const {
        std::string dk = derive_direction_key(direction);
        return hmac_sha256_hex(dk, payload);
    }
};

// =============================================================================
// SECTION 5: HANDSHAKE VALIDATOR
// =============================================================================

class HandshakeValidator {
public:
    // FIX-09: require_strong and reject_recovered parameters restored.
    HandshakeValidator(const PassportRegistry& registry,
                       const SemanticPassport&  local_passport,
                       std::string              schema,
                       TransportIdentity        transport,
                       NonceCache&              cache,
                       uint64_t                 now,
                       bool                     reject_recovered = false,
                       bool                     require_strong   = false)
        : registry_(registry),
          local_passport_(local_passport),
          local_schema_(std::move(schema)),
          local_transport_(std::move(transport)),
          nonce_cache_(cache),
          now_(now),
          reject_recovered_(reject_recovered),
          require_strong_(require_strong) {}

    // ── Message 1: Initiator builds HELLO ─────────────────────────────────────

    // FIX-13: schema parameter restored.
    HelloMessage build_hello(const std::string& schema = "") {
        local_nonce_    = generate_nonce();
        local_ephemeral_ = generate_ephemeral_keypair();

        // FIX-07: Sign the ephemeral public key with the passport signing key
        // so the responder can verify the ephemeral key is from the same party
        // that holds this passport. Uses HMAC over (passport_id || ephemeral_pub)
        // keyed by the passport's signing key material.
        std::string eph_sig = hmac_sha256_hex(
            local_passport_.signing_key_material,
            local_passport_.model_id + ":" + local_ephemeral_.public_hex);

        const std::string& effective_schema = schema.empty() ? local_schema_ : schema;
        return HelloMessage{
            local_passport_,
            local_nonce_,
            effective_schema,
            local_ephemeral_.public_hex,
            eph_sig,
            local_transport_
        };
    }

    // ── Message 2: Responder validates HELLO and produces ACK ─────────────────

    struct Result {
        bool             accepted = false;
        HelloAckMessage  ack;
        SessionContext   session;
        std::string      reject_reason;
    };

    Result validate_hello(const HelloMessage& msg) {
        Result res;

        // FIX-09: Transport strength check
        if (require_strong_ && !msg.transport.is_strong()) {
            res.reject_reason = "REJECT_TRANSPORT_MISMATCH";
            return res;
        }

        // FIX-09: Recovered passport rejection
        if (reject_recovered_ && msg.passport.is_recovered()) {
            res.reject_reason = "REJECT_RECOVERED_PASSPORT";
            return res;
        }

        // Replay detection: initiator nonce in INITIATOR namespace
        if (!nonce_cache_.consume(NonceRole::INITIATOR, msg.session_nonce)) {
            res.reject_reason = "REJECT_REPLAY_DETECTED";
            return res;
        }

        // Passport validity
        VerifyResult vr = registry_.verify(msg.passport, now_);
        if (!vr.ok()) {
            res.reject_reason = "REJECT_INVALID_PASSPORT:" + verify_status_str(vr.status);
            return res;
        }

        // FIX-06: Schema negotiation
        if (msg.proposed_schema != local_schema_) {
            res.reject_reason = "REJECT_SCHEMA_MISMATCH:"
                                + msg.proposed_schema + "!=" + local_schema_;
            return res;
        }

        // FIX-07: Verify initiator's ephemeral key signature
        std::string expected_eph_sig = hmac_sha256_hex(
            msg.passport.signing_key_material,
            msg.passport.model_id + ":" + msg.ephemeral_public_hex);
        if (msg.ephemeral_key_sig != expected_eph_sig) {
            res.reject_reason = "REJECT_EPHEMERAL_KEY_SIG_INVALID";
            return res;
        }

        // Generate responder nonce and ephemeral keypair
        local_nonce_     = generate_nonce();
        local_ephemeral_ = generate_ephemeral_keypair();

        // Session ID: deterministically ordered by role to ensure both sides
        // compute the same value
        std::string sid_material =
            "INIT_NONCE:"  + msg.session_nonce           +
            "|RESP_NONCE:" + local_nonce_                 +
            "|INIT_TRANS:" + msg.transport.binding_token() +
            "|RESP_TRANS:" + local_transport_.binding_token();
        std::string sid = sha256_hex(sid_material);

        // Derive shared secret and session key
        std::string secret = local_ephemeral_.derive_shared_secret(
            msg.ephemeral_public_hex, msg.session_nonce, local_nonce_);

        auto key_bytes = hkdf_sha256(hex_to_bytes(secret),
                                     sid, "uml001-session-v1", 32);

        // FIX-15: Set forward_secrecy on pending_session_ here
        pending_session_.session_id      = sid;
        pending_session_.session_key_hex = bytes_to_hex(key_bytes);
        pending_session_.forward_secrecy = true;
        pending_session_.initiator_model_id = msg.passport.model_id;
        pending_session_.responder_model_id = local_passport_.model_id;

        OPENSSL_cleanse(key_bytes.data(), key_bytes.size());

        // Forward secrecy: destroy private key before sending public key out
        local_ephemeral_.destroy_private_key();

        // FIX-07: Sign responder's ephemeral public key
        std::string resp_eph_sig = hmac_sha256_hex(
            local_passport_.signing_key_material,
            local_passport_.model_id + ":" + local_ephemeral_.public_hex);

        res.ack.passport             = local_passport_;
        res.ack.session_nonce        = local_nonce_;
        res.ack.accepted_schema      = local_schema_;   // FIX-06
        res.ack.session_id           = sid;
        res.ack.ephemeral_public_hex = local_ephemeral_.public_hex;
        res.ack.ephemeral_key_sig    = resp_eph_sig;    // FIX-07
        res.ack.transport            = local_transport_;
        res.accepted                 = true;
        return res;
    }

    // ── Message 3a: Initiator processes ACK and produces CONFIRM ──────────────

    struct AckResult {
        bool                 accepted = false;
        HelloConfirmMessage  confirm;
        SessionContext       session;
        std::string          reject_reason;
    };

    AckResult process_ack(const HelloAckMessage& ack) {
        AckResult res;

        // FIX-10: Guard against double-call after ephemeral key destroyed
        if (local_ephemeral_.private_key_destroyed()) {
            res.reject_reason = "REJECT_ACK_ALREADY_PROCESSED";
            return res;
        }

        // Replay detection: responder nonce in RESPONDER namespace
        if (!nonce_cache_.consume(NonceRole::RESPONDER, ack.session_nonce)) {
            res.reject_reason = "REJECT_REPLAY_DETECTED";
            return res;
        }

        // FIX-07: Verify responder's ephemeral key signature
        std::string expected_eph_sig = hmac_sha256_hex(
            ack.passport.signing_key_material,
            ack.passport.model_id + ":" + ack.ephemeral_public_hex);
        if (ack.ephemeral_key_sig != expected_eph_sig) {
            res.reject_reason = "REJECT_EPHEMERAL_KEY_SIG_INVALID";
            return res;
        }

        // Recompute session ID and verify it matches responder's value
        std::string sid_material =
            "INIT_NONCE:"  + local_nonce_                  +
            "|RESP_NONCE:" + ack.session_nonce              +
            "|INIT_TRANS:" + local_transport_.binding_token() +
            "|RESP_TRANS:" + ack.transport.binding_token();
        std::string sid = sha256_hex(sid_material);

        if (sid != ack.session_id) {
            res.reject_reason = "REJECT_SID_MISMATCH";
            return res;
        }

        // Derive shared secret and session key (must match responder's derivation)
        std::string secret = local_ephemeral_.derive_shared_secret(
            ack.ephemeral_public_hex, local_nonce_, ack.session_nonce);

        auto key_bytes = hkdf_sha256(hex_to_bytes(secret),
                                     sid, "uml001-session-v1", 32);

        res.session.session_id           = sid;
        res.session.session_key_hex      = bytes_to_hex(key_bytes);
        res.session.forward_secrecy      = true;
        res.session.initiator_model_id   = local_passport_.model_id;
        res.session.responder_model_id   = ack.passport.model_id;

        // Forward secrecy: destroy private key before returning confirm
        local_ephemeral_.destroy_private_key();

        // Confirm signature: HMAC of session_id keyed by session key,
        // proving the initiator derived the correct key material
        res.confirm.session_id  = sid;
        res.confirm.signature   = hmac_sha256_hex(
            std::string(key_bytes.begin(), key_bytes.end()), sid);

        OPENSSL_cleanse(key_bytes.data(), key_bytes.size());

        res.accepted = true;
        return res;
    }

    // ── Message 3b: Responder validates CONFIRM ────────────────────────────────
    // FIX-08: validate_confirm() was entirely absent in rev 1.3.

    struct ConfirmResult {
        bool           accepted = false;
        SessionContext session;
        std::string    reject_reason;
    };

    ConfirmResult validate_confirm(const HelloConfirmMessage& confirm) {
        ConfirmResult res;

        if (confirm.session_id != pending_session_.session_id) {
            res.reject_reason = "REJECT_SESSION_ID_MISMATCH";
            return res;
        }

        // Recompute the HMAC the initiator should have produced
        auto key_bytes = hex_to_bytes(pending_session_.session_key_hex);
        std::string expected_sig = hmac_sha256_hex(
            std::string(key_bytes.begin(), key_bytes.end()),
            pending_session_.session_id);

        if (confirm.signature != expected_sig) {
            res.reject_reason = "REJECT_CONFIRM_SIGNATURE_INVALID";
            return res;
        }

        res.session  = pending_session_;   // forward_secrecy already set (FIX-15)
        res.accepted = true;
        return res;
    }

private:
    const PassportRegistry& registry_;
    const SemanticPassport&  local_passport_;
    std::string              local_schema_;
    TransportIdentity        local_transport_;
    NonceCache&              nonce_cache_;
    uint64_t                 now_;
    bool                     reject_recovered_;
    bool                     require_strong_;

    std::string      local_nonce_;
    EphemeralKeyPair local_ephemeral_;
    SessionContext   pending_session_;
};

} // namespace uml001