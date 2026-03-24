#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>

namespace uml001 {

/**
 * @brief Configuration for ColdVault storage
 */
struct VaultConfig {
    std::string vault_path = "var/uml001/audit.vault";
    std::string archive_dir = "var/uml001/archive";
    size_t rotate_after_bytes = 1073741824;      // 1GB
    size_t rotate_after_entries = 1000000;       // 1M entries
    bool compress_on_archive = true;
};

/**
 * @brief Audit vault entry record
 */
struct VaultEntry {
    std::string type;
    std::string session_id;
    std::string actor_id;
    std::string payload_hash;
    std::string metadata;
    uint64_t timestamp;
};

class Vault {
public:
    virtual ~Vault() = default;
    virtual bool store(const std::string& key, const std::vector<uint8_t>& data) = 0;
    virtual std::optional<std::vector<uint8_t>> retrieve(const std::string& key) = 0;
};

/**
 * @brief High-security storage for audit events and long-term keys
 * [E-7] Provenance logging with BFT quality metrics
 */
class ColdVault : public Vault {
public:
    explicit ColdVault(const VaultConfig& cfg = VaultConfig());
    ~ColdVault() override = default;

    bool store(const std::string& key, const std::vector<uint8_t>& data) override;
    std::optional<std::vector<uint8_t>> retrieve(const std::string& key) override;

    /**
     * @brief Appends an audit event to the vault
     * @param type Event type (e.g., "SESSION_START", "ENTROPY_FLUSH", "SESSION_QUARANTINE")
     * @param session_id Session identifier
     * @param actor_id Actor/peer identifier
     * @param payload_hash Hash of the associated payload
     * @param metadata Machine-readable metadata (e.g., "unc_ms=50|status=BFT_SYNC")
     * @param timestamp Unix timestamp in seconds
     */
    void append(const std::string& type, 
                const std::string& session_id, 
                const std::string& actor_id,
                const std::string& payload_hash, 
                const std::string& metadata, 
                uint64_t timestamp);

    size_t entry_count() const { return entries_.size(); }

private:
    VaultConfig cfg_;
    std::map<std::string, std::vector<uint8_t>> secure_storage_;
    std::vector<VaultEntry> entries_;
};

} // namespace uml001
