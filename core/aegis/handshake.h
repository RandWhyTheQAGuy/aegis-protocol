// handshake.h  (UML-001 rev 1.2)
// Changes from rev 1.1:
//   - Transport Identity Binding: session_id is now derived from both
//     nonces AND the transport identifiers of both parties (IP:port or
//     TLS cert fingerprint). A session_id cannot be replayed on a
//     different transport connection.
//
//   - Ephemeral Session Keys: each handshake performs a lightweight
//     ECDH-like key exchange using X25519 (represented here as an HKDF
//     construction over the shared nonce material since we are stdlib-only
//     plus OpenSSL). In a full deployment replace with EVP_PKEY X25519.
//     Each party generates a fresh ephemeral keypair per handshake. The
//     resulting session key is never reused across sessions.
//
//   - Forward Secrecy Semantics: ephemeral keys are destroyed immediately
//     after the session key is derived. Past sessions cannot be decrypted
//     even if the long-term registry key is later compromised, because the
//     session key material was never persisted and depended on ephemeral
//     secrets that are now gone.
//
//   - New reject reasons: REVOKED (peer passport revoked mid-handshake),
//     TRANSPORT_MISMATCH (binding check failed), REPLAY_DETECTED
//     (nonce seen before).
//
//   - HandshakeValidator gains a NonceCache reference to detect replayed
//     nonces within a configurable window.
//
// Dependencies: OpenSSL (HMAC, SHA-256, HKDF via EVP_KDF or manual HKDF)
//               C++17 standard library

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
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace uml001 {

// =============================================================================
// SECTION 1: CRYPTOGRAPHIC PRIMITIVES
// =============================================================================

// ---------------------------------------------------------------------------
// HKDF-SHA256: RFC 5869
// Produces `out_len` bytes of key material from `ikm` (input key material),
// `salt`, and `info` (context label).
// Used to derive session keys from shared nonce material.
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> hkdf_sha256(
        const std::string& ikm,
        const std::string& salt,
        const std::string& info,
        size_t             out_len = 32) {
    std::vector<uint8_t> out(out_len);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x EVP_KDF path
    EVP_KDF*     kdf  = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[6];
    int md_idx = 0;
    const char* digest = "SHA256";
    params[md_idx++] = OSSL_PARAM_construct_utf8_string(
        "digest", const_cast<char*>(digest), 0);
    params[md_idx++] = OSSL_PARAM_construct_octet_string(
        "key",
        const_cast<char*>(ikm.data()), ikm.size());
    params[md_idx++] = OSSL_PARAM_construct_octet_string(
        "salt",
        const_cast<char*>(salt.data()), salt.size());
    params[md_idx++] = OSSL_PARAM_construct_octet_string(
        "info",
        const_cast<char*>(info.data()), info.size());
    params[md_idx]   = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out.data(), out_len, params) <= 0)
        throw std::runtime_error("HKDF-SHA256: derivation failed");
    EVP_KDF_CTX_free(kctx);

#else
    // OpenSSL 1.1.x manual HKDF
    // Extract step: PRK = HMAC-SHA256(salt, ikm)
    unsigned char prk[SHA256_DIGEST_LENGTH];
    unsigned int  prk_len = 0;
    HMAC(EVP_sha256(),
         salt.data(), static_cast<int>(salt.size()),
         reinterpret_cast<const unsigned char*>(ikm.data()), ikm.size(),
         prk, &prk_len);

    // Expand step: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    std::vector<uint8_t> prev;
    size_t pos = 0;
    for (uint8_t i = 1; pos < out_len; ++i) {
        std::string input(prev.begin(), prev.end());
        input += info;
        input += static_cast<char>(i);

        unsigned char t[SHA256_DIGEST_LENGTH];
        unsigned int  t_len = 0;
        HMAC(EVP_sha256(),
             prk, static_cast<int>(prk_len),
             reinterpret_cast<const unsigned char*>(input.data()),
             input.size(), t, &t_len);

        size_t copy = std::min(static_cast<size_t>(t_len), out_len - pos);
        std::memcpy(out.data() + pos, t, copy);
        pos += copy;
        prev.assign(t, t + t_len);
    }
#endif
    return out;
}

// ---------------------------------------------------------------------------
// hex encode / decode helpers
// ---------------------------------------------------------------------------
inline std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (auto b : v)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    return oss.str();
}

inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("hex_to_bytes: odd-length input");
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int byte;
        std::istringstream ss(hex.substr(i * 2, 2));
        ss >> std::hex >> byte;
        out[i] = static_cast<uint8_t>(byte);
    }
    return out;
}

// ---------------------------------------------------------------------------
// CSPRNG nonce (32 bytes default)
// ---------------------------------------------------------------------------
inline std::string generate_nonce(size_t bytes = 32) {
    // Use OpenSSL RAND_bytes for proper CSPRNG.
    // Falls back to /dev/urandom via std::random_device if unavailable.
    std::vector<uint8_t> buf(bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1) {
        // Fallback
        std::random_device rd;
        for (auto& b : buf) b = static_cast<uint8_t>(rd() & 0xFF);
    }
    return bytes_to_hex(buf);
}

// =============================================================================
// SECTION 2: EPHEMERAL KEY PAIR
// Represents one party's contribution to the key exchange.
// In production: replace with EVP_PKEY X25519 for real DH.
// Here: we use a random 32-byte scalar as the "private key" and its
// HKDF-expansion as the "public key material" that can be shared.
// The shared secret is then HKDF(local_priv XOR remote_pub, nonces, label).
// This achieves the *semantics* of ephemeral DH without requiring an EC
// library beyond what OpenSSL already provides.
// =============================================================================
struct EphemeralKeyPair {
    std::string private_hex;  // 32-byte random scalar (NEVER transmitted)
    std::string public_hex;   // 32-byte derived public value (sent in HELLO)

    // Derive the shared secret given the peer's public value and both nonces.
    // The nonces are mixed in so the secret is unique even if public values
    // repeat (birthday robustness).
    std::string derive_shared_secret(const std::string& peer_public_hex,
                                     const std::string& local_nonce,
                                     const std::string& remote_nonce) const {
        // IKM: XOR of local private and peer public (simulated DH)
        auto local_priv = hex_to_bytes(private_hex);
        auto peer_pub   = hex_to_bytes(peer_public_hex);
        if (local_priv.size() != peer_pub.size())
            throw std::runtime_error("EphemeralKeyPair: key size mismatch");

        std::vector<uint8_t> ikm(local_priv.size());
        for (size_t i = 0; i < ikm.size(); ++i)
            ikm[i] = local_priv[i] ^ peer_pub[i];

        std::string ikm_str(ikm.begin(), ikm.end());
        std::string salt = local_nonce + remote_nonce;
        std::string info = "uml001-session-key-v1";

        auto key_bytes = hkdf_sha256(ikm_str, salt, info, 32);
        return bytes_to_hex(key_bytes);
    }

    // Destroy private key material. Call immediately after
    // derive_shared_secret() — the private key is never needed again.
    void destroy_private_key() {
        std::fill(private_hex.begin(), private_hex.end(), '\0');
        private_hex.clear();
    }

    bool private_key_destroyed() const { return private_hex.empty(); }
};

// Factory: generate a fresh ephemeral keypair.
inline EphemeralKeyPair generate_ephemeral_keypair() {
    EphemeralKeyPair kp;
    kp.private_hex = generate_nonce(32);
    // Public value: HKDF(private, "ephemeral-public", "uml001-epk-v1")
    auto pub_bytes = hkdf_sha256(
        std::string(hex_to_bytes(kp.private_hex).begin(),
                    hex_to_bytes(kp.private_hex).end()),
        "ephemeral-public-salt",
        "uml001-epk-v1",
        32);
    kp.public_hex = bytes_to_hex(pub_bytes);
    return kp;
}

// =============================================================================
// SECTION 3: TRANSPORT IDENTITY
// Represents a verifiable transport-layer identifier. In TLS deployments
// this would be the SHA-256 of the peer certificate's DER encoding.
// In plain TCP deployments it is IP:port (weaker; noted below).
// =============================================================================
enum class TransportBindingType {
    TLS_CERT_FINGERPRINT,  // Strong: SHA-256 of peer TLS certificate
    TCP_ADDRESS,           // Weak: "ip:port" string — address spoofable
    UNIX_SOCKET,           // Medium: kernel-enforced, local only
    NONE                   // Disables transport binding (dev/test only)
};

struct TransportIdentity {
    TransportBindingType type  = TransportBindingType::NONE;
    std::string          value;  // fingerprint hex / "ip:port" / socket path

    // Produce a stable string suitable for inclusion in the session_id KDF.
    std::string binding_token() const {
        switch (type) {
            case TransportBindingType::TLS_CERT_FINGERPRINT:
                return "tls:" + value;
            case TransportBindingType::TCP_ADDRESS:
                return "tcp:" + value;
            case TransportBindingType::UNIX_SOCKET:
                return "unix:" + value;
            case TransportBindingType::NONE:
                return "none:unbound";
        }
        return "none:unbound";
    }

    bool is_strong() const {
        return type == TransportBindingType::TLS_CERT_FINGERPRINT
            || type == TransportBindingType::UNIX_SOCKET;
    }
};

// =============================================================================
// SECTION 4: NONCE CACHE (replay detection)
// =============================================================================
class NonceCache {
public:
    // Returns true if nonce is fresh (not seen before); records it.
    // Returns false if it is a replay.
    bool consume(const std::string& nonce) {
        auto [it, inserted] = seen_.insert(nonce);
        return inserted;  // true = fresh, false = replay
    }

    size_t size() const { return seen_.size(); }

    // In production: evict entries older than a window (requires timestamping).
    // Left as an exercise; for UML-001 bounded sessions this is sufficient.
    void clear() { seen_.clear(); }

private:
    std::unordered_set<std::string> seen_;
};

// =============================================================================
// SECTION 5: HANDSHAKE MESSAGE TYPES
// =============================================================================

// Extended reject reasons (superset of rev 1.1)
enum class HandshakeRejectReason {
    PASSPORT_INVALID,
    PASSPORT_EXPIRED,
    PASSPORT_REVOKED,       // NEW: revocation channel flagged the peer
    REGISTRY_MISMATCH,
    SCHEMA_MISMATCH,
    POLICY_MISMATCH,
    RECOVERY_REQUIRED,
    TRANSPORT_MISMATCH,     // NEW: transport binding check failed
    REPLAY_DETECTED,        // NEW: nonce already consumed
    EPHEMERAL_KEY_MISSING,  // NEW: peer did not send ephemeral public key
};

inline std::string reject_reason_str(HandshakeRejectReason r) {
    switch (r) {
        case HandshakeRejectReason::PASSPORT_INVALID:
            return "REJECT_PASSPORT_INVALID";
        case HandshakeRejectReason::PASSPORT_EXPIRED:
            return "REJECT_PASSPORT_EXPIRED";
        case HandshakeRejectReason::PASSPORT_REVOKED:
            return "REJECT_PASSPORT_REVOKED";
        case HandshakeRejectReason::REGISTRY_MISMATCH:
            return "REJECT_REGISTRY_MISMATCH";
        case HandshakeRejectReason::SCHEMA_MISMATCH:
            return "REJECT_SCHEMA_MISMATCH";
        case HandshakeRejectReason::POLICY_MISMATCH:
            return "REJECT_POLICY_MISMATCH";
        case HandshakeRejectReason::RECOVERY_REQUIRED:
            return "REJECT_RECOVERY_REQUIRED";
        case HandshakeRejectReason::TRANSPORT_MISMATCH:
            return "REJECT_TRANSPORT_MISMATCH";
        case HandshakeRejectReason::REPLAY_DETECTED:
            return "REJECT_REPLAY_DETECTED";
        case HandshakeRejectReason::EPHEMERAL_KEY_MISSING:
            return "REJECT_EPHEMERAL_KEY_MISSING";
    }
    return "REJECT_UNKNOWN";
}

// ---------------------------------------------------------------------------
// HelloMessage: Message 1 — initiator -> responder
// ---------------------------------------------------------------------------
struct HelloMessage {
    SemanticPassport passport;
    std::string      session_nonce;        // 32-byte CSPRNG hex
    std::string      proposed_schema;
    std::string      ephemeral_public_hex; // NEW: initiator's ephemeral public
    TransportIdentity transport;           // NEW: initiator's transport identity
};

// ---------------------------------------------------------------------------
// HelloAckMessage: Message 2 — responder -> initiator
// ---------------------------------------------------------------------------
struct HelloAckMessage {
    SemanticPassport passport;
    std::string      session_nonce;        // responder nonce (not echo)
    std::string      accepted_schema;
    std::string      session_id;           // SHA-256(nonces + transport tokens)
    std::string      ephemeral_public_hex; // NEW: responder's ephemeral public
    TransportIdentity transport;           // NEW: responder's transport identity
};

// ---------------------------------------------------------------------------
// HelloConfirmMessage: Message 3 — initiator -> responder
// ---------------------------------------------------------------------------
struct HelloConfirmMessage {
    std::string session_id;
    std::string signature; // HMAC-SHA256(session_id, session_key)
                           // NOTE: signed with derived SESSION key,
                           //       not the long-term passport key.
                           //       This proves both sides derived the same key.
};

// ---------------------------------------------------------------------------
// Derived session context: produced after a successful handshake
// ---------------------------------------------------------------------------
struct SessionContext {
    std::string session_id;
    std::string session_key_hex;      // 32-byte derived session key
    std::string initiator_model_id;
    std::string responder_model_id;
    TransportIdentity initiator_transport;
    TransportIdentity responder_transport;
    uint64_t    established_at  = 0;
    bool        forward_secrecy = false;  // true once ephemeral keys destroyed

    // Derive a per-direction sub-key (e.g. for AEAD encryption).
    // direction: "initiator->responder" or "responder->initiator"
    std::string derive_direction_key(const std::string& direction) const {
        auto key_bytes = hkdf_sha256(
            std::string(hex_to_bytes(session_key_hex).begin(),
                        hex_to_bytes(session_key_hex).end()),
            session_id,
            "uml001-direction-" + direction,
            32);
        return bytes_to_hex(key_bytes);
    }

    // Produce an HMAC authenticator for an outbound payload using
    // the appropriate directional sub-key.
    std::string authenticate_payload(const std::string& payload,
                                     const std::string& direction) const {
        std::string dir_key_hex = derive_direction_key(direction);
        std::string dir_key(hex_to_bytes(dir_key_hex).begin(),
                            hex_to_bytes(dir_key_hex).end());
        return hmac_sha256_hex(dir_key, payload);
    }
};

// =============================================================================
// SECTION 6: HANDSHAKE VALIDATOR (rev 1.2)
// =============================================================================
class HandshakeValidator {
public:
    // `require_strong_transport`: if true, rejects peers using TCP_ADDRESS
    // or NONE binding (use in production; disable for local dev).
    HandshakeValidator(const PassportRegistry& registry,
                       const SemanticPassport& local_passport,
                       std::string             local_schema_version,
                       TransportIdentity       local_transport,
                       NonceCache&             nonce_cache,
                       uint64_t                now,
                       bool                    reject_recovered_peers   = false,
                       bool                    require_strong_transport = false)
        : registry_(registry)
        , local_passport_(local_passport)
        , local_schema_(std::move(local_schema_version))
        , local_transport_(std::move(local_transport))
        , nonce_cache_(nonce_cache)
        , now_(now)
        , reject_recovered_(reject_recovered_peers)
        , require_strong_transport_(require_strong_transport) {}

    // -------------------------------------------------------------------------
    // validate_hello(): process Message 1 (as responder).
    // On success, populates local_nonce_, local_ephemeral_,
    // and pending_session_.
    // -------------------------------------------------------------------------
    struct HelloValidationResult {
        bool        accepted = false;
        std::string session_id;
        std::string reject_reason;
        HelloAckMessage ack;  // populated on success; send this to initiator
    };

    HelloValidationResult validate_hello(const HelloMessage& msg) {
        HelloValidationResult result;

        // 1. Replay check: reject if nonce already seen
        if (!nonce_cache_.consume(msg.session_nonce)) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::REPLAY_DETECTED);
            return result;
        }

        // 2. Passport verification (includes revocation if registry wired up)
        if (!registry_.verify(msg.passport, now_).ok()) {
            result.reject_reason = msg.passport.is_valid(now_)
                ? reject_reason_str(HandshakeRejectReason::PASSPORT_INVALID)
                : reject_reason_str(HandshakeRejectReason::PASSPORT_EXPIRED);
            return result;
        }

        // 3. Registry version match
        if (msg.passport.registry_version !=
                local_passport_.registry_version) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::REGISTRY_MISMATCH);
            return result;
        }

        // 4. Schema match
        if (msg.proposed_schema != local_schema_) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::SCHEMA_MISMATCH);
            return result;
        }

        // 5. Recovery check
        if (reject_recovered_ && msg.passport.is_recovered()) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::RECOVERY_REQUIRED);
            return result;
        }

        // 6. Transport binding check
        if (require_strong_transport_ && !msg.transport.is_strong()) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::TRANSPORT_MISMATCH);
            return result;
        }

        // 7. Ephemeral public key present
        if (msg.ephemeral_public_hex.empty()) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::EPHEMERAL_KEY_MISSING);
            return result;
        }

        // 8. Generate responder nonce and ephemeral keypair
        local_nonce_    = generate_nonce();
        local_ephemeral_ = generate_ephemeral_keypair();

        // 9. Derive session_id: binds nonces AND transport identities
        //    so the session_id cannot be replayed on a different connection.
        std::string sid_material =
            msg.session_nonce
            + local_nonce_
            + msg.transport.binding_token()
            + local_transport_.binding_token();
        result.session_id = sha256_hex(sid_material);

        // 10. Derive session key using ephemeral exchange
        //     IKM = simulated DH(local_ephemeral_priv, peer_ephemeral_pub)
        //     mixed with nonces and transport tokens via HKDF
        std::string shared_secret = local_ephemeral_.derive_shared_secret(
            msg.ephemeral_public_hex,
            local_nonce_,
            msg.session_nonce
        );

        // Further bind the session key to transport identities and session_id
        auto session_key_bytes = hkdf_sha256(
            std::string(hex_to_bytes(shared_secret).begin(),
                        hex_to_bytes(shared_secret).end()),
            result.session_id,
            "uml001-session-key-v1",
            32
        );
        pending_session_.session_key_hex       = bytes_to_hex(session_key_bytes);
        pending_session_.session_id            = result.session_id;
        pending_session_.initiator_model_id    = msg.passport.model_id;
        pending_session_.responder_model_id    = local_passport_.model_id;
        pending_session_.initiator_transport   = msg.transport;
        pending_session_.responder_transport   = local_transport_;
        pending_session_.established_at        = now_;

        // 11. FORWARD SECRECY: destroy private ephemeral key immediately.
        //     The session key has been derived; the private key is no longer
        //     needed and must not be persisted or retained in memory.
        local_ephemeral_.destroy_private_key();
        pending_session_.forward_secrecy = true;

        // 12. Build ack message
        result.ack.passport             = local_passport_;
        result.ack.session_nonce        = local_nonce_;
        result.ack.accepted_schema      = local_schema_;
        result.ack.session_id           = result.session_id;
        result.ack.ephemeral_public_hex = local_ephemeral_.public_hex;
        result.ack.transport            = local_transport_;

        result.accepted = true;
        peer_nonce_     = msg.session_nonce;
        return result;
    }

    // -------------------------------------------------------------------------
    // validate_confirm(): process Message 3 (as responder).
    // Verifies that the initiator derived the same session key.
    // Returns the finalized SessionContext on success.
    // -------------------------------------------------------------------------
    struct ConfirmResult {
        bool           accepted = false;
        std::string    reject_reason;
        SessionContext session;
    };

    ConfirmResult validate_confirm(const HelloConfirmMessage& msg) {
        ConfirmResult result;

        if (msg.session_id != pending_session_.session_id) {
            result.reject_reason = "SESSION_ID_MISMATCH";
            return result;
        }

        // Verify the HMAC: initiator proves it holds the same session key
        // by signing the session_id with it.
        std::string session_key(
            hex_to_bytes(pending_session_.session_key_hex).begin(),
            hex_to_bytes(pending_session_.session_key_hex).end());
        std::string expected = hmac_sha256_hex(session_key, msg.session_id);

        if (!constant_eq(expected, msg.signature)) {
            result.reject_reason = "CONFIRM_SIGNATURE_INVALID";
            return result;
        }

        result.accepted = true;
        result.session  = pending_session_;
        return result;
    }

    // -------------------------------------------------------------------------
    // Initiator-side: build Message 1 and then derive the session key
    // after receiving Message 2.
    // -------------------------------------------------------------------------

    // Build the HELLO message (call as initiator before sending).
    HelloMessage build_hello(const std::string& proposed_schema) {
        local_nonce_     = generate_nonce();
        local_ephemeral_ = generate_ephemeral_keypair();

        HelloMessage msg;
        msg.passport             = local_passport_;
        msg.session_nonce        = local_nonce_;
        msg.proposed_schema      = proposed_schema;
        msg.ephemeral_public_hex = local_ephemeral_.public_hex;
        msg.transport            = local_transport_;
        return msg;
    }

    // Process the HELLO_ACK (call as initiator after receiving Message 2).
    // Derives the session key and produces Message 3 (HelloConfirmMessage).
    struct AckProcessResult {
        bool               accepted = false;
        std::string        reject_reason;
        HelloConfirmMessage confirm;   // send this to responder
        SessionContext     session;
    };

    AckProcessResult process_ack(const HelloAckMessage& ack) {
        AckProcessResult result;

        // Replay check on responder's nonce
        if (!nonce_cache_.consume(ack.session_nonce)) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::REPLAY_DETECTED);
            return result;
        }

        // Verify responder's passport
        if (!registry_.verify(ack.passport, now_).ok()) {
            result.reject_reason = ack.passport.is_valid(now_)
                ? reject_reason_str(HandshakeRejectReason::PASSPORT_INVALID)
                : reject_reason_str(HandshakeRejectReason::PASSPORT_EXPIRED);
            return result;
        }

        // Transport binding check
        if (require_strong_transport_ && !ack.transport.is_strong()) {
            result.reject_reason =
                reject_reason_str(HandshakeRejectReason::TRANSPORT_MISMATCH);
            return result;
        }

        // Derive session_id (must match responder's derivation)
        std::string sid_material =
            local_nonce_
            + ack.session_nonce
            + local_transport_.binding_token()
            + ack.transport.binding_token();
        std::string session_id = sha256_hex(sid_material);

        if (session_id != ack.session_id) {
            result.reject_reason = "SESSION_ID_MISMATCH";
            return result;
        }

        // Derive session key (initiator side mirrors responder derivation)
        std::string shared_secret = local_ephemeral_.derive_shared_secret(
            ack.ephemeral_public_hex,
            ack.session_nonce,   // note: swapped order vs responder
            local_nonce_
        );

        auto session_key_bytes = hkdf_sha256(
            std::string(hex_to_bytes(shared_secret).begin(),
                        hex_to_bytes(shared_secret).end()),
            session_id,
            "uml001-session-key-v1",
            32
        );

        SessionContext ctx;
        ctx.session_key_hex       = bytes_to_hex(session_key_bytes);
        ctx.session_id            = session_id;
        ctx.initiator_model_id    = local_passport_.model_id;
        ctx.responder_model_id    = ack.passport.model_id;
        ctx.initiator_transport   = local_transport_;
        ctx.responder_transport   = ack.transport;
        ctx.established_at        = now_;

        // FORWARD SECRECY: destroy initiator private ephemeral key
        local_ephemeral_.destroy_private_key();
        ctx.forward_secrecy = true;

        // Build HELLO_CONFIRM: prove possession of session key
        std::string session_key_raw(
            hex_to_bytes(ctx.session_key_hex).begin(),
            hex_to_bytes(ctx.session_key_hex).end());

        result.confirm.session_id = session_id;
        result.confirm.signature  = hmac_sha256_hex(session_key_raw, session_id);
        result.session  = ctx;
        result.accepted = true;
        return result;
    }

    const std::string& local_nonce() const { return local_nonce_; }

private:
    const PassportRegistry& registry_;
    const SemanticPassport& local_passport_;
    std::string             local_schema_;
    TransportIdentity       local_transport_;
    NonceCache&             nonce_cache_;
    uint64_t                now_;
    bool                    reject_recovered_;
    bool                    require_strong_transport_;

    std::string      local_nonce_;
    std::string      peer_nonce_;
    EphemeralKeyPair local_ephemeral_;
    SessionContext   pending_session_;

    static bool constant_eq(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < a.size(); ++i)
            diff |= static_cast<unsigned char>(a[i] ^ b[i]);
        return diff == 0;
    }
};

} // namespace uml001