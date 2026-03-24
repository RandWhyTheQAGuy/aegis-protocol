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
// Configuration & Security Thresholds [E-8]
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

        // 3. Registry & Transparency Log Initialization
        TransparencyLog t_log(get_clock(), TransparencyMode::IMMEDIATE);
        PassportRegistry registry(ROOT_KEY, REG_VERSION, get_clock());
        
        // 4. Multi-Party Issuance [E-6]
        std::vector<std::string> signers = {"op-alpha", "op-beta", "op-gamma"};
        MultiPartyIssuer mp_issuer(signers, 2, REG_VERSION, t_log);

        std::cout << "[STEP 1] Proposing Multi-Party Passport for 'model-nexus'...\n";
        auto proposal_id = mp_issuer.propose("op-alpha", ROOT_KEY, "model-nexus", 
                                            "2.1.0", Capabilities{}, "policy_v2_hash", 
                                            get_clock()->now_unix());

        std::cout << "[STEP 2] Countersigning (Achieving 2/3 Quorum)...\n";
        mp_issuer.countersign("op-beta", ROOT_KEY, proposal_id, get_clock()->now_unix());

        // 5. Session Initialization & Warp State Transitions [E-4, E-8]
        auto flush_callback = [&](const std::string& sid, const std::string& inc, const std::vector<std::string>& t) {
            std::cout << "[EVENT] Entropy Flush: Incident " << inc << " for Session " << sid << "\n";
            vault.append("ENTROPY_FLUSH", sid, "system", inc, "tainted_count=" + std::to_string(t.size()), get_clock()->now_unix());
        };

        Session session("sess-omega", "model-nexus", WARP_SUSPECT_THRESH, flush_callback);
        session.activate();
        vault_log_event(vault, "SESSION_START", "sess-omega", "model-nexus", "0000", bft_ptr);

        // 6. Driving Warp Transitions (ACTIVE -> SUSPECT -> QUARANTINE)
        std::cout << "[STEP 3] Simulating Policy Violations...\n";
        
        PolicyDecision threat;
        threat.action = PolicyAction::DENY;
        threat.risk_weight = 1.5f; // [E-8] Accelerated warp score
        threat.payload_hash = "bad_payload_hash_001";

        // This should trigger the SUSPECT state
        session.process_decision(threat, get_clock()->now_ms());
        std::cout << "[SESSION] State: " << Session::state_str(session.state()) 
                  << " | Warp Score: " << session.warp_score() << "\n";

        // This should trigger the QUARANTINE state (Fail-Closed) [E-4]
        threat.payload_hash = "bad_payload_hash_002";
        session.process_decision(threat, get_clock()->now_ms());
        
        std::cout << "[SESSION] Final State: " << Session::state_str(session.state()) << "\n";

        if (session.state() == SessionState::QUARANTINE) {
            vault_log_event(vault, "SESSION_QUARANTINE", "sess-omega", "model-nexus", threat.payload_hash, bft_ptr);
        }

        std::cout << "--- Aegis Protocol Execution Complete ---\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[FATAL ERROR] Aegis Protocol Halted: " << e.what() << "\n";
        return 1;
    }
}