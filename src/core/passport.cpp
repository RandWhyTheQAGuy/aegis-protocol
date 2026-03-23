#include "uml001/core/passport.h"
#include <iostream>

namespace uml001 {

// This ensures every Passport issued is timestamped by our BFT Quorum
void Passport::issue(std::shared_ptr<IClock> clock) {
    if (!clock) {
        throw std::runtime_error("Cannot issue passport without a trusted clock.");
    }
    
    this->issuance_timestamp = clock->now_unix();
    this->status = PassportStatus::ACTIVE;
    
    std::cout << "[Passport] Issued new passport at BFT Time: " 
              << this->issuance_timestamp << std::endl;
}

} // namespace uml001