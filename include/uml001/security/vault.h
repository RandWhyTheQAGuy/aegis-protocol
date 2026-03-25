#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>

namespace uml001 {

struct VaultConfig {
    std::string vault_path = "var/uml001/audit.vault";
    std::string archive_dir = "var/uml001/archives/";
    uint64_t rotate_after_bytes = 64ULL * 1024 * 1024;
    uint64_t rotate_after_entries = 500000;
    bool compress_on_archive = true;
};

class Vault {
public:
    virtual ~Vault() = default;
    virtual bool store(const std::string& key, const std::vector<uint8_t>& data) = 0;
    virtual std::optional<std::vector<uint8_t>> retrieve(const std::string& key) = 0;
};

// High-security storage for long-term keys
class ColdVault : public Vault {
public:
    explicit ColdVault(const VaultConfig& cfg = VaultConfig())
        : cfg_(cfg), entries_(), next_entry_id_(0) {}

    bool store(const std::string& key, const std::vector<uint8_t>& data) override {
        secure_storage_[key] = data;
        return true;
    }
    std::optional<std::vector<uint8_t>> retrieve(const std::string& key) override {
        auto it = secure_storage_.find(key);
        if (it == secure_storage_.end()) return std::nullopt;
        return it->second;
    }

    void append(const std::string& event_type,
                const std::string& session_id,
                const std::string& actor_id,
                const std::string& payload_hash,
                const std::string& metadata,
                uint64_t ts) {
        (void)event_type;
        (void)session_id;
        (void)actor_id;
        (void)payload_hash;
        (void)metadata;
        (void)ts;
        entries_.push_back("entry-" + std::to_string(next_entry_id_++));
    }

    uint64_t entry_count() const {
        return static_cast<uint64_t>(entries_.size());
    }

private:
    VaultConfig cfg_;
    std::map<std::string, std::vector<uint8_t>> secure_storage_;
    std::vector<std::string> entries_;
    uint64_t next_entry_id_;
};

} // namespace uml001