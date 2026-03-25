#pragma once

#include "uml001/crypto/crypto_utils.h"
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <memory> // Added for std::shared_ptr

namespace uml001 {

// Forward declaration of the clock interface
class IClock;

enum class PassportStatus {
    INACTIVE,
    ACTIVE,
    REVOKED
};

// VerifyResult: Contains information about passport verification
enum class VerifyStatus {
    OK = 0,
    EXPIRED = 1,
    REVOKED = 2,
    INVALID_SIGNATURE = 3,
    INCOMPATIBLE = 4
};

struct VerifyResult {
    VerifyStatus status = VerifyStatus::OK;
    uint32_t verified_key_id = 0;
    bool recovered = false;
    float confidence = 0.0f;
    
    bool ok() const {
        return status == VerifyStatus::OK;
    }
    
    std::string status_str() const {
        switch (status) {
            case VerifyStatus::OK: return "OK";
            case VerifyStatus::EXPIRED: return "EXPIRED";
            case VerifyStatus::REVOKED: return "REVOKED";
            case VerifyStatus::INVALID_SIGNATURE: return "INVALID_SIGNATURE";
            case VerifyStatus::INCOMPATIBLE: return "INCOMPATIBLE";
        }
        return "UNKNOWN";
    }
};

struct Capabilities {
    bool classifier_authority = false;
    bool classifier_sensitivity = false;
    bool bft_consensus = false;
    bool entropy_flush = false;

    std::string serialize() const {
        return std::string(classifier_authority ? "1" : "0") +
               (classifier_sensitivity ? "1" : "0") +
               (bft_consensus ? "1" : "0") +
               (entropy_flush ? "1" : "0");
    }
};

struct Passport {
    std::string model_id;
    std::string model_version;
    Capabilities capabilities;
    std::string policy_hash;
    
    // Updated to match the logic in passport.cpp
    uint64_t issued_at = 0; 
    uint64_t expires_at = 0;
    PassportStatus status = PassportStatus::INACTIVE; 

    uint32_t signing_key_id = 0;
    std::string signature;
    std::optional<std::string> recovery_token;
    
    // Cryptographic material for HMAC operations
    std::string signing_key_material;
    
    // Registry version this passport was issued under
    std::string registry_version;
    
    // Check if this passport has been recovered
    bool is_recovered() const {
        return recovery_token.has_value();
    }
    
    // Check if this passport is still valid at the given time
    bool is_valid(uint64_t now) const {
        return status == PassportStatus::ACTIVE && 
               now >= issued_at && 
               now < expires_at;
    }
    
    // Compute a canonical representation for signing/HMAC operations
    std::string canonical_body() const {
        return model_id + "|" + model_version + "|" + 
               capabilities.serialize() + "|" + 
               policy_hash + "|" + 
               std::to_string(issued_at) + "|" + 
               std::to_string(expires_at) + "|" + 
               registry_version;
    }

    // The function the compiler was looking for
    void issue(std::shared_ptr<IClock> clock);

    std::string content_hash() const {
        std::string raw = model_id + "|" + model_version + "|" + 
                          capabilities.serialize() + "|" + 
                          policy_hash + "|" + 
                          std::to_string(issued_at) + "|" + 
                          std::to_string(expires_at);
        return sha256_hex(raw);
    }
};

// SemanticPassport: A read-only view of passport data for handshake & serialization
// Maps to Passport but provides a cleaner interface for external use
using SemanticPassport = Passport;

class PassportRegistry {
public:
    // Using references here as per your original design
    PassportRegistry(class TransparencyLog& log, class RevocationList& list, class IClock& clock)
        : log_(log), revocation_list_(list), clock_(clock) {}

    Passport issue_model_passport(
        const std::string& model_id,
        const std::string& version,
        const Capabilities& caps,
        const std::string& policy_hash,
        uint32_t key_id
    );
    
    VerifyResult verify(const Passport& passport) const;

private:
    class TransparencyLog& log_;
    class RevocationList&  revocation_list_;
    class IClock&          clock_;
};

} // namespace uml001