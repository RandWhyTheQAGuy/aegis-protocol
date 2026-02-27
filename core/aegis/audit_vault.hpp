#pragma once
#include <string>
#include <fstream>
#include <sstream>
#include <mutex>
#include <iomanip>
#include <stdexcept>
#include <openssl/sha.h>

namespace uml001 {

// Reusing the SHA-256 utility from the Passport component
inline std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::ostringstream oss;
    for (auto b : hash)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

struct AuditEntry {
    uint64_t timestamp;
    std::string session_id;
    std::string agent_id;
    std::string action;        // ALLOW, DENY, FLAG
    std::string payload_hash;
    float warp_score;
    std::string previous_hash; // Link to the previous entry
    std::string current_hash;  // Hash of (previous_hash + current_data)

    // Serializes the core data for hashing
    std::string canonical_data() const {
        std::ostringstream oss;
        oss << timestamp << "|" << session_id << "|" << agent_id << "|" 
            << action << "|" << payload_hash << "|" << warp_score << "|" 
            << previous_hash;
        return oss.str();
    }
};

class ColdAuditVault {
public:
    ColdAuditVault(const std::string& filepath) : filepath_(filepath) {
        // Initialize or read the last hash to maintain the chain across restarts
        std::ifstream infile(filepath_);
        if (infile.good()) {
            std::string line, last_line;
            while (std::getline(infile, line)) {
                if (!line.empty()) last_line = line;
            }
            if (!last_line.empty()) {
                // Extract the last hash from the JSON/CSV-like structure
                // Assuming format: current_hash is the last field
                size_t pos = last_line.find_last_of('|');
                if (pos != std::string::npos) {
                    last_hash_ = last_line.substr(pos + 1);
                }
            }
        } else {
            last_hash_ = "GENESIS_HASH_00000000000000000000000000000000";
        }
    }

    AuditEntry append_record(uint64_t timestamp, const std::string& session_id,
                             const std::string& agent_id, const std::string& action,
                             const std::string& payload_hash, float warp_score) {
        std::lock_guard<std::mutex> lock(vault_mutex_);

        AuditEntry entry;
        entry.timestamp = timestamp;
        entry.session_id = session_id;
        entry.agent_id = agent_id;
        entry.action = action;
        entry.payload_hash = payload_hash;
        entry.warp_score = warp_score;
        entry.previous_hash = last_hash_;
        
        // Calculate the chained hash
        entry.current_hash = sha256_hex(entry.canonical_data());

        // Write to append-only log
        std::ofstream outfile(filepath_, std::ios_base::app);
        if (!outfile) throw std::runtime_error("UML-001: Cannot open audit vault file.");

        outfile << entry.timestamp << "|" << entry.session_id << "|" 
                << entry.agent_id << "|" << entry.action << "|" 
                << entry.payload_hash << "|" << entry.warp_score << "|" 
                << entry.previous_hash << "|" << entry.current_hash << "\n";
        
        outfile.flush();
        last_hash_ = entry.current_hash;

        return entry;
    }

    std::string get_last_hash() const {
        std::lock_guard<std::mutex> lock(vault_mutex_);
        return last_hash_;
    }

private:
    std::string filepath_;
    std::string last_hash_;
    mutable std::mutex vault_mutex_; // Ensures thread-safe file appends
};

} // namespace uml001