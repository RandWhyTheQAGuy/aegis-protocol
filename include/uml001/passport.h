#pragma once

#include "uml001/crypto_utils.h"
#include <string>
#include <vector>
#include <map>

namespace uml001 {

struct Passport {
    std::string passport_id;
    std::string subject_id;
    std::string issuer_id;
    uint64_t    issued_at = 0;
    uint64_t    expires_at = 0;
    
    std::map<std::string, std::string> attributes;
    std::vector<std::string> roles;
    std::vector<std::string> permissions;
    
    std::string signature_hex;

    std::string content_hash() const {
        return sha256_hex(subject_id + "|" + std::to_string(issued_at) + "|" + issuer_id);
    }
};

class PassportRegistry {
public:
    PassportRegistry(class TransparencyLog& log, class RevocationList& list, class IClock& clock)
        : log_(log), revocation_list_(list), clock_(clock) {}

    Passport issue(const std::string& subject_id, 
                   const std::map<std::string, std::string>& attrs,
                   const std::string& issuer_id);
    
    bool verify(const Passport& passport);

private:
    class TransparencyLog& log_;
    class RevocationList&  revocation_list_;
    class IClock&          clock_;
};

}