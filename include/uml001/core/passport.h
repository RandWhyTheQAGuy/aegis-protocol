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
    
    bool verify(const Passport& passport);

private:
    class TransparencyLog& log_;
    class RevocationList&  revocation_list_;
    class IClock&          clock_;
};

} // namespace uml001