/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * The Aegis Protocol defines a distributed trust and identity framework
 * based on cryptographically verifiable Semantic Passports, capability
 * enforcement, and transparency logging for auditable system behavior.
 *
 * Core components include:
 *   - Semantic Passports: verifiable identity and capability attestations
 *   - Transparency Log: append-only cryptographic audit trail of system events
 *   - Revocation System: deterministic invalidation of compromised or expired identities
 *   - Passport Registry: issuance and verification authority for trusted entities
 *
 * This framework is designed for open standardization, interoperability,
 * and production-grade use in distributed identity, AI systems, and
 * verifiable authorization infrastructures.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for research, verifiable systems design,
 * and deployment in security-critical distributed environments.
 */
#include "uml001/core/bft_clock_client.h"
#include "uml001/core/clock.h"
#include "uml001/core/passport.h"
#include "uml001/security/revocation.h"
#include "uml001/security/transparency_log.h"
#include "uml001/security/vault.h"
#include "uml001/crypto/crypto_utils.h"

#include <iostream>
#include <memory>
#include <cstdlib>

namespace uml001 {

// ==============================
// Global Clock Management
// ==============================
static std::shared_ptr<IClock> g_active_clock = nullptr;

void init_clock(std::shared_ptr<IClock> clock) { g_active_clock = clock; }
std::shared_ptr<IClock> get_clock() { return g_active_clock; }

// ==============================
// Mock Clock (CI / fallback)
// ==============================
class MockClock : public IClock {
public:
    uint64_t now_unix() const override { return 1740000000ULL; }
    uint64_t now_ms() const override { return 1740000000000ULL; }
    ClockStatus status() const override { return ClockStatus::SYNCHRONIZED; }

    bool is_synchronized() const override { return true; }
    uint64_t last_sync_unix() const override { return 1740000000ULL; }
    std::string source_id() const override { return "mock_ci_clock"; }
};

// ==============================
// Vault Logging Helper
// ==============================
static void vault_log_event(ColdVault& vault,
                            const std::string& type,
                            const std::string& sess,
                            const std::string& actor,
                            const std::string& payload_hash,
                            const BftClockClient* bft) {
    std::string provenance = "system=aegis-protocol";

    if (bft) {
        provenance += "|unc_ms=" + std::to_string(bft->now_ms() % 100)
                   + "|status=BFT_SYNC";
    }

    vault.append(type,
                 sess,
                 actor,
                 payload_hash,
                 provenance,
                 get_clock()->now_unix());
}

} // namespace uml001

// ==============================
// MAIN ENTRY POINT
// ==============================
int main(int argc, char** argv) {
    using namespace uml001;

    try {
        std::cout << "--- Aegis Protocol Production Host Initializing ---\n";

        // ==============================
        // Vault Initialization
        // ==============================
        VaultConfig v_cfg;
        v_cfg.vault_path = "var/uml001/audit.vault";
        ColdVault vault(v_cfg);

        // ==============================
        // Clock Initialization
        // ==============================
        std::shared_ptr<IClock> active_clock;
        BftClockClient* bft_ptr = nullptr;

        if (std::getenv("UML001_CI_MODE")) {
            active_clock = std::make_shared<MockClock>();
        } else {
            BftClockClientConfig c_cfg;
            c_cfg.target_uri = "unix:///var/run/uml001/bft-clock.sock";

            auto bft = std::make_shared<BftClockClient>(c_cfg);
            bft_ptr = bft.get();
            active_clock = bft;
        }

        init_clock(active_clock);

        // ==============================
        // 🔥 CRITICAL FIX: ORDER MATTERS
        // ==============================

        // 1. Create Transparency Log FIRST
        TransparencyLog tlog(get_clock(), TransparencyMode::IMMEDIATE);

        // 2. Then RevocationList (depends on tlog)
        RevocationList revocation_list(tlog);

        // 3. Then PassportRegistry (depends on both)
        PassportRegistry registry(tlog, revocation_list, *get_clock(), vault);

        // ==============================
        // Example Flow
        // ==============================
        Capabilities caps;
        caps.classifier_authority = true;

        auto passport = registry.issue_model_passport(
            "agent-alpha",
            "1.0.0",
            caps,
            sha256_hex("policy"),
            1
        );

        std::cout << "[VERIFY] "
                  << registry.verify(passport).status_str()
                  << "\n";

        vault_log_event(
            vault,
            "SYSTEM_START",
            "main",
            "system",
            sha256_hex("startup"),
            bft_ptr
        );

        std::cout << "[DONE]\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }
}