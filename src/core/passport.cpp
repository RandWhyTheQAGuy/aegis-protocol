#include "uml001/core/passport.h"
#include "uml001/core/clock.h" // Ensure the full definition of IClock is visible
#include <iostream>
#include <stdexcept>

namespace uml001 {

void Passport::issue(std::shared_ptr<IClock> clock) {
    if (!clock) {
        throw std::runtime_error("Cannot issue passport without a trusted clock.");
    }
    
    // Updated to match the header field 'issued_at'
    this->issued_at = clock->now_unix();
    this->status = PassportStatus::ACTIVE;
    
    std::cout << "[Passport] Issued new passport for model " << model_id 
              << " at BFT Time: " << this->issued_at << std::endl;
}

} // namespace uml001