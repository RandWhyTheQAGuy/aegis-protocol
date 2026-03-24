#pragma once

#include "uml001/security/transparency_log.h"
#include <string>
#include <set>

namespace uml001 {

class RevocationList {
public:
    // We pass by reference to ensure the list is tied to a specific log instance
    explicit RevocationList(TransparencyLog& log) : log_(log) {}

    void propose_revocation(const std::string& model_id, const std::string& reason);
    void approve_revocation(const std::string& proposal_id);
    void finalize_revocation(const std::string& model_id);

    bool is_revoked(const std::string& model_id) const {
        return revoked_models_.find(model_id) != revoked_models_.end();
    }

private:
    TransparencyLog& log_;
    std::set<std::string> revoked_models_;
};

} // namespace uml001