// handshake.h
    #pragma once
    #include "passport.h"
    #include <random>
    #include <algorithm>

    namespace uml002 {

    // ---------------------------------------------------------------------------
    // Generate a cryptographically random hex nonce (simplified; use
    // /dev/urandom or OS CSPRNG in production)
    // ---------------------------------------------------------------------------
    inline std::string generate_nonce(size_t bytes = 32) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        std::ostringstream oss;
        for (size_t i = 0; i < bytes; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(dist(gen));
        return oss.str();
    }

    enum class HandshakeRejectReason {
        PASSPORT_INVALID,
        PASSPORT_EXPIRED,
        REGISTRY_MISMATCH,
        SCHEMA_MISMATCH,
        POLICY_MISMATCH,
        RECOVERY_REQUIRED
    };

    inline std::string reject_reason_str(HandshakeRejectReason r) {
        switch (r) {
            case HandshakeRejectReason::PASSPORT_INVALID:
                return "REJECT_PASSPORT_INVALID";
            case HandshakeRejectReason::PASSPORT_EXPIRED:
                return "REJECT_PASSPORT_EXPIRED";
            case HandshakeRejectReason::REGISTRY_MISMATCH:
                return "REJECT_REGISTRY_MISMATCH";
            case HandshakeRejectReason::SCHEMA_MISMATCH:
                return "REJECT_SCHEMA_MISMATCH";
            case HandshakeRejectReason::POLICY_MISMATCH:
                return "REJECT_POLICY_MISMATCH";
            case HandshakeRejectReason::RECOVERY_REQUIRED:
                return "REJECT_RECOVERY_REQUIRED";
        }
        return "REJECT_UNKNOWN";
    }

    struct HandshakeResult {
        bool        accepted   = false;
        std::string session_id;
        std::string reject_reason;
    };

    // ---------------------------------------------------------------------------
    // HandshakeValidator: validates an inbound HELLO and produces a session_id
    // ---------------------------------------------------------------------------
    class HandshakeValidator {
    public:
        HandshakeValidator(const PassportRegistry& registry,
                           const SemanticPassport& local_passport,
                           std::string             local_schema_version,
                           uint64_t                now,
                           bool                    reject_recovered_peers = false)
            : registry_(registry)
            , local_passport_(local_passport)
            , local_schema_(std::move(local_schema_version))
            , now_(now)
            , reject_recovered_(reject_recovered_peers) {}

        // Validate a peer's passport and nonce. Returns a HandshakeResult.
        HandshakeResult validate_hello(const SemanticPassport& peer_passport,
                                       const std::string& peer_nonce,
                                       const std::string& peer_schema) {
            HandshakeResult result;

            if (!registry_.verify(peer_passport, now_)) {
                result.reject_reason = peer_passport.is_valid(now_)
                    ? reject_reason_str(HandshakeRejectReason::PASSPORT_INVALID)
                    : reject_reason_str(HandshakeRejectReason::PASSPORT_EXPIRED);
                return result;
            }

            if (peer_passport.registry_version !=
                local_passport_.registry_version) {
                result.reject_reason =
                    reject_reason_str(HandshakeRejectReason::REGISTRY_MISMATCH);
                return result;
            }

            if (peer_schema != local_schema_) {
                result.reject_reason =
                    reject_reason_str(HandshakeRejectReason::SCHEMA_MISMATCH);
                return result;
            }

            if (reject_recovered_ && peer_passport.is_recovered()) {
                result.reject_reason =
                    reject_reason_str(HandshakeRejectReason::RECOVERY_REQUIRED);
                return result;
            }

            // Generate responder nonce and derive session_id
            local_nonce_       = generate_nonce();
            result.session_id  = sha256_hex(peer_nonce + local_nonce_);
            result.accepted    = true;
            return result;
        }

        const std::string& local_nonce() const { return local_nonce_; }

    private:
        const PassportRegistry& registry_;
        const SemanticPassport& local_passport_;
        std::string             local_schema_;
        uint64_t                now_;
        bool                    reject_recovered_;
        std::string             local_nonce_;
    };

    } // namespace uml002
