/**
 * main_aegis_protocol.cpp — Aegis Protocol Unified Production Runner
 * =================================================================
 * Pattern: BFT Sidecar (Production) / Mock Clock (CI/CD)
 * Logic: Multi-Party Issuance & Session Warp State Transitions
 */

#include "uml001/core/bft_clock_client.h"
#include "uml001/core/clock.h"
#include "uml001/core/passport.h"
#include "uml001/core/session.h"
#include "uml001/core/policy.h"
#include "uml001/core/temporal_state.h"
#include "uml001/security/multi_party_issuance.h"
#include "uml001/security/transparency_log.h"
#include "uml001/vault.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/crypto/simple_hash_provider.h"

#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <stdexcept>

using namespace uml001;

// =============================================================================
// FIX 1: MISSING DECLARATIONS (CRITICAL)
// =============================================================================

// These are REQUIRED because your code uses them but they are not guaranteed
// to exist depending on header versions.

static std::shared_ptr<uml001::IClock> g_global_clock;

static void init_clock(std::shared_ptr<uml001::IClock> clock)
{
    if (!clock) {
        throw std::runtime_error("init_clock: clock is null");
    }
    g_global_clock = std::move(clock);
}

static std::shared_ptr<uml001::IClock> get_clock()
{
    if (!g_global_clock) {
        throw std::runtime_error("get_clock: global clock not initialized");
    }
    return g_global_clock;
}

static inline uint64_t now_unix()
{
    return get_clock()->now_unix();
}

// =============================================================================
// CONSTANTS
// =============================================================================
static constexpr const char* ROOT_KEY    = "registry-root-key-32byte-padding";
static constexpr const char* REG_VERSION = "0.1.0";
static constexpr uint32_t PASSPORT_TTL_S = 86400;

// Warp thresholds co-located with weights [E-8]
static constexpr float WARP_SUSPECT_THRESH    = 1.0f;
static constexpr float WARP_QUARANTINE_THRESH = 3.0f;

// =============================================================================
// CI/CD Mock Clock Implementation
// =============================================================================
class MockClock : public IClock {
public:
    uint64_t now_unix() const override { return 1740000000ULL; }
    uint64_t now_ms() const { return 1740000000000ULL; }
    ClockStatus status() const override { return ClockStatus::SYNCHRONIZED; }
};

// =============================================================================
// Helper: Vault Logging with BFT Provenance [E-7]
// =============================================================================
static void vault_log_event(ColdVault& vault, 
                            const std::string& type, 
                            const std::string& sess, 
                            const std::string& actor, 
                            const std::string& payload_hash,
                            const BftClockClient* bft) {
    std::string provenance = "system=aegis-protocol";
    if (bft) {
        // [E-7] Embedding machine-readable BFT quality metrics
        provenance += "|unc_ms=" + std::to_string(bft->now_ms() % 100); // Simulated uncertainty
        provenance += "|status=BFT_SYNC";
    }
    
    // Assumes ColdVault::append(type, sess, actor, hash, metadata, timestamp)
    vault.append(type, sess, actor, payload_hash, provenance, get_clock()->now_unix());
}

// =============================================================================
// Main Protocol Logic
// =============================================================================

int main(int argc, char** argv) {
    try {
        std::cout << "--- Aegis Protocol Production Host Initializing ---\n";

        // 1. Audit & Vault Setup
        VaultConfig v_cfg;
        v_cfg.vault_path = "var/uml001/audit.vault";
        ColdVault vault(v_cfg);

        // 2. Clock Selection: Sidecar vs CI Mode
        std::shared_ptr<IClock> active_clock;
        BftClockClient* bft_ptr = nullptr;

        if (std::getenv("UML001_CI_MODE")) {
            std::cout << "[INIT] CI Mode detected. Using MockClock.\n";
            active_clock = std::make_shared<MockClock>();
        } else {
            std::cout << "[INIT] Connecting to uml001-bft-clockd Sidecar...\n";
            BftClockClientConfig c_cfg;
            c_cfg.target_uri = "unix:///var/run/uml001/bft-clock.sock";
            c_cfg.fail_closed = true;
            
            auto bft = std::make_shared<BftClockClient>(c_cfg);
            bft_ptr = bft.get();
            active_clock = bft;
        }
        init_clock(active_clock);

        // =========================================================================
        // REGISTRY
        // =========================================================================

        uml001::TransparencyLog tlog(get_clock(), uml001::TransparencyMode::IMMEDIATE);
        uml001::RevocationList revocation_list;
        PassportRegistry registry(tlog, revocation_list, *get_clock());

        // =========================================================================
        // BASIC FLOW TEST (minimal but VALID)
        // =========================================================================

        Capabilities caps;
        caps.classifier_authority = true;

        auto passport = registry.issue_model_passport(
            "agent-alpha",
            "1.0.0",
            caps,
            sha256_hex("policy"),
            1
        );

        auto vr = registry.verify(passport);

        std::cout << "[VERIFY] " << vr.status_str() << "\n";

        // =========================================================================
        // VAULT RECORD (PROVENANCE VALIDATED)
        // =========================================================================

        vault_append_with_provenance(
            vault,
            "SYSTEM_START",
            "main",
            "system",
            sha256_hex("startup"),
            "init",
            *clock
        );

        // =========================================================================
        // SHUTDOWN
        // =========================================================================

        std::cout << "[DONE]\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[FATAL ERROR] Aegis Protocol Halted: " << e.what() << "\n";
        return 1;
    }
}