#pragma once

#include "uml001/crypto_utils.h"
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <map>

namespace uml001 {

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
    uint64_t issued_at = 0;
    uint64_t expires_at = 0;
    uint32_t signing_key_id = 0;
    std::string signature;
    std::optional<std::string> recovery_token;

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