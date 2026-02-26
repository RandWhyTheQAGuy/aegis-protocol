// passport.h
    #pragma once
    #include <string>
    #include <cstdint>
    #include <optional>
    #include <stdexcept>
    #include <sstream>
    #include <iomanip>
    #include <openssl/hmac.h>
    #include <openssl/sha.h>

    namespace uml001 {

    // ---------------------------------------------------------------------------
    // SHA-256 utility
    // ---------------------------------------------------------------------------
    inline std::string sha256_hex(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.data()),
               data.size(), hash);
        std::ostringstream oss;
        for (auto b : hash)
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(b);
        return oss.str();
    }

    // ---------------------------------------------------------------------------
    // HMAC-SHA256 utility
    // ---------------------------------------------------------------------------
    inline std::string hmac_sha256_hex(const std::string& key,
                                       const std::string& data) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int  len = 0;
        HMAC(EVP_sha256(),
             key.data(),  static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(data.data()),
             data.size(), hash, &len);
        std::ostringstream oss;
        for (unsigned int i = 0; i < len; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
        return oss.str();
    }

    // ---------------------------------------------------------------------------
    // Passport capabilities flags
    // ---------------------------------------------------------------------------
    struct Capabilities {
        bool classifier_authority   = false;
        bool classifier_sensitivity = false;
        bool bft_consensus          = false;
        bool entropy_flush          = false;
    };

    // ---------------------------------------------------------------------------
    // SemanticPassport
    // ---------------------------------------------------------------------------
    struct SemanticPassport {
        std::string  passport_version  = "0.1";
        std::string  model_id;
        std::string  model_version;
        std::string  protocol          = "UML-001";
        std::string  registry_version;
        Capabilities capabilities;
        std::string  policy_hash;
        uint64_t     issued_at         = 0;
        uint64_t     expires_at        = 0;
        std::string  recovery_token;   // empty if not a recovered node
        std::string  signature;

        bool is_valid(uint64_t now) const {
            return !model_id.empty()
                && !registry_version.empty()
                && now >= issued_at
                && now <  expires_at;
        }

        bool is_recovered() const {
            return !recovery_token.empty();
        }

        // Produce canonical body string for signing (simplified serialization).
        // In production, use a proper JSON library with sorted keys.
        std::string canonical_body() const {
            std::ostringstream s;
            s << "capabilities.bft_consensus="    << capabilities.bft_consensus
              << "&capabilities.classifier_authority="
              << capabilities.classifier_authority
              << "&capabilities.classifier_sensitivity="
              << capabilities.classifier_sensitivity
              << "&capabilities.entropy_flush="   << capabilities.entropy_flush
              << "&expires_at="     << expires_at
              << "&issued_at="      << issued_at
              << "&model_id="       << model_id
              << "&model_version="  << model_version
              << "&passport_version=" << passport_version
              << "&policy_hash="    << policy_hash
              << "&protocol="       << protocol
              << "&recovery_token=" << recovery_token
              << "&registry_version=" << registry_version;
            return s.str();
        }

        // Sign this passport with the registry key.
        void sign(const std::string& registry_key) {
            signature = hmac_sha256_hex(registry_key, canonical_body());
        }

        // Verify signature.
        bool verify(const std::string& registry_key) const {
            std::string expected =
                hmac_sha256_hex(registry_key, canonical_body());
            // Constant-time comparison to prevent timing attacks
            if (expected.size() != signature.size()) return false;
            unsigned char diff = 0;
            for (size_t i = 0; i < expected.size(); ++i)
                diff |= static_cast<unsigned char>(expected[i] ^ signature[i]);
            return diff == 0;
        }
    };

    // ---------------------------------------------------------------------------
    // PassportRegistry: issues and verifies passports
    // ---------------------------------------------------------------------------
    class PassportRegistry {
    public:
        explicit PassportRegistry(std::string root_key,
                                  std::string registry_version)
            : root_key_(std::move(root_key))
            , registry_version_(std::move(registry_version)) {}

        SemanticPassport issue(const std::string& model_id,
                               const std::string& model_version,
                               const Capabilities& caps,
                               const std::string& policy_hash,
                               uint64_t now,
                               uint64_t ttl_seconds = 86400) const {
            SemanticPassport p;
            p.model_id         = model_id;
            p.model_version    = model_version;
            p.registry_version = registry_version_;
            p.capabilities     = caps;
            p.policy_hash      = policy_hash;
            p.issued_at        = now;
            p.expires_at       = now + ttl_seconds;
            p.sign(root_key_);
            return p;
        }

        bool verify(const SemanticPassport& p, uint64_t now) const {
            if (p.registry_version != registry_version_) return false;
            if (!p.is_valid(now)) return false;
            return p.verify(root_key_);
        }

        SemanticPassport issue_recovery_token(
                SemanticPassport p,
                const std::string& incident_id,
                uint64_t now,
                uint64_t ttl_seconds = 3600) const {
            p.recovery_token = "RECOVERY:" + incident_id;
            p.issued_at      = now;
            p.expires_at     = now + ttl_seconds;
            p.sign(root_key_);
            return p;
        }

    private:
        std::string root_key_;
        std::string registry_version_;
    };

    } // namespace uml001
