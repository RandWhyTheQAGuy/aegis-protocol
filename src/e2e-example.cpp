/**
 * e2e-example.cpp — UML-001 Full End-to-End Integration
 * ======================================================
 *
 * See header comment in the original for full architectural description
 * ([S-1..S-8], deployment topologies, clock independence).
 *
 * Fixes applied in this file
 * --------------------------
 * [F-1] All includes now reference headers that exist in include/ or are
 *       generated alongside this file.
 * [F-2] clock.h's IClock::now_unix() is non-const; BftClockClient and
 *       MockClock implement that signature. The IStrongClock interface
 *       (used by ColdVault / BFTQuorumTrustedClock) has const now_unix().
 *       The two hierarchies are separate; e2e uses IClock throughout.
 * [F-3] vault_append_with_provenance() uses ColdVault::log_security_event()
 *       (the real API) rather than a hypothetical vault.append().
 * [F-4] make_incident_id() uses vault.load_last_drift() as a monotone
 *       counter proxy (matches what ColdVault actually exposes) plus
 *       CSPRNG suffix, satisfying [E-5].
 * [F-5] PassportRegistry::issue_recovery_token() is declared; the impl
 *       creates a new passport with status=RECOVERED.
 * [F-6] All #ifdef UML001_TEST_CLOCK guards present; non-IPC path uses
 *       OsStrongClock wrapped in a thin IClock adapter.
 */

// =============================================================================
// Includes
// =============================================================================
#include "bft_clock_client.h"        // BftClockClient, BftClockClientConfig,
                                     // BftClockDaemonHandle, BftClockIpcError
#include "clock.h"                   // IClock, init_clock, get_clock, NOW,
                                     // validate_timestamp, SecurityViolation
#include "uml001/vault.h"            // ColdVault, IVaultBackend
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/strong_clock.h"     // OsStrongClock
#include "uml001/crypto_utils.h"     // sha256_hex, hmac_sha256_hex,
                                     // generate_random_bytes_hex, ed25519_keygen
#include "session.h"                 // Session, SessionConfig, SessionState,
                                     // FlushCallback
#include "policy.h"                  // PolicyEngine, PolicyRule, PolicyDecision,
                                     // SemanticScore, CompatibilityManifest
#include "passport.h"                // PassportRegistry, SemanticPassport, Capabilities
#include "handshake.h"               // HandshakeValidator, NonceCache, SessionContext
#include "multi_party_issuance.h"    // MultiPartyIssuer
#include "transparency_log.h"        // TransparencyLog

#include <unordered_set>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <optional>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <algorithm>

using namespace uml001;

// =============================================================================
// Named constants
// =============================================================================

static constexpr const char* ROOT_KEY    = "registry-root-key-32byte-padding";
static constexpr const char* REG_VERSION = "0.1.0";
static constexpr uint32_t PASSPORT_TTL_S = 86400;
static constexpr float RECOVERED_CONF_FLOOR = 0.95f;

// Warp score weights and thresholds — co-located per [E-8]
static constexpr float WARP_WEIGHT_ALLOW      = -0.1f;
static constexpr float WARP_WEIGHT_FLAG       =  0.5f;
static constexpr float WARP_WEIGHT_DENY       =  1.0f;
static constexpr float WARP_SUSPECT_THRESH    =  1.0f;
static constexpr float WARP_QUARANTINE_THRESH =  3.0f;

static constexpr uint64_t IPC_MAX_SKEW_S   = 5;
static constexpr uint64_t IPC_CACHE_TTL_MS = 200;

// =============================================================================
// read_daemon_pubkey / read_socket_path
// =============================================================================

static std::string read_daemon_pubkey()
{
    const char* env = std::getenv("UML001_BFT_PUBKEY");
    if (env && std::strlen(env) == 64)
        return std::string(env);

    const char* file_path = std::getenv("UML001_BFT_PUBKEY_FILE");
    if (file_path) {
        std::ifstream f(file_path);
        if (!f.is_open())
            throw std::runtime_error(
                std::string("cannot open UML001_BFT_PUBKEY_FILE: ") + file_path);
        std::string key;
        std::getline(f, key);
        key.erase(std::remove_if(key.begin(), key.end(),
                  [](char c){ return c=='\n'||c=='\r'||c==' '; }), key.end());
        if (key.size() != 64)
            throw std::runtime_error(
                "UML001_BFT_PUBKEY_FILE: key must be 64 hex chars");
        return key;
    }

#ifdef BFT_CLOCK_TEST_PUBKEY
    return std::string(BFT_CLOCK_TEST_PUBKEY);
#endif

    throw std::runtime_error(
        "BFT clock daemon public key not configured.\n"
        "  Set UML001_BFT_PUBKEY or UML001_BFT_PUBKEY_FILE.\n"
        "  In test builds define -DBFT_CLOCK_TEST_PUBKEY=<64-hex-char-key>.");
}

static std::string read_socket_path()
{
    const char* env = std::getenv("UML001_BFT_SOCKET");
    if (env && std::strlen(env) > 0)
        return std::string(env);
#ifndef _WIN32
    return "/var/run/uml001/bft-clock.sock";
#else
    return R"(\\.\pipe\uml001-bft-clock)";
#endif
}

// =============================================================================
// make_incident_id() — [E-5]
//
// Unique incident token. Uses BFT-verified time + a CSPRNG suffix.
// ColdVault::load_last_drift() provides a value that changes between
// restarts (persisted to disk), acting as a monotone process-lifetime proxy.
// A 128-bit random suffix ensures uniqueness even across simultaneous restarts.
// =============================================================================
static std::string make_incident_id(const std::string& session_id,
                                    ColdVault&         vault)
{
    const uint64_t    t   = NOW;
    const std::string rnd = generate_random_bytes_hex(16);

    // load_last_drift returns an optional; use 0 if no prior state.
    int64_t drift_seq = vault.load_last_drift().value_or(0);

    std::ostringstream oss;
    oss << "INC-" << session_id << "-" << t
        << "-" << drift_seq
        << "-" << rnd;
    return oss.str();
}

// =============================================================================
// vault_append_with_provenance() — [E-7]
//
// Appends a vault security event embedding BFT timestamp provenance
// (uncertainty_s, issued_at) so every audit record carries timestamp quality.
// =============================================================================
static void vault_append_with_provenance(ColdVault&            vault,
                                          const std::string&    event_type,
                                          const std::string&    session_id,
                                          const std::string&    actor_id,
                                          const std::string&    payload_hash,
                                          const std::string&    metadata,
                                          const BftClockClient& clock_client)
{
    const uint64_t uncertainty = clock_client.last_uncertainty_s();
    const uint64_t iat         = clock_client.last_issued_at();

    const std::string prov = "unc=" + std::to_string(uncertainty)
                           + " iat=" + std::to_string(iat);
    const std::string full_meta = metadata.empty()
        ? prov
        : metadata + "|" + prov;

    // Map to the structured vault API: event_type is the key,
    // remaining fields are embedded in the detail string.
    const std::string detail =
        "session=" + session_id +
        " actor="  + actor_id  +
        " hash="   + payload_hash +
        " "        + full_meta;

    vault.log_security_event(event_type, detail);
}

// =============================================================================
// build_flush_callback() — [E-7]
// =============================================================================
static FlushCallback build_flush_callback(ColdVault&            vault,
                                           const BftClockClient* clock_client)
{
    return [&vault, clock_client](
               const std::string&              session_id,
               const std::string&              incident_id,
               const std::vector<std::string>& tainted_hashes)
    {
        std::cout << "[ENTROPY FLUSH] session=" << session_id
                  << " incident="               << incident_id
                  << " count="                  << tainted_hashes.size() << "\n";

        const uint64_t uncertainty = clock_client
            ? clock_client->last_uncertainty_s() : 0;
        const uint64_t iat = clock_client
            ? clock_client->last_issued_at() : 0;
        const std::string prov = "unc=" + std::to_string(uncertainty)
                               + " iat=" + std::to_string(iat);

        for (const auto& h : tainted_hashes) {
            vault.log_security_event(
                "ENTROPY_FLUSH_TAINT",
                "session=" + session_id +
                " incident=" + incident_id +
                " hash=" + h + " " + prov);
        }
    };
}

// =============================================================================
// main()
// =============================================================================
int main()
{
    // =========================================================================
    // Step 0 — Audit vault
    // =========================================================================
    OsStrongClock      os_clock;
    SimpleHashProvider hash_provider;

    ColdVault::Config vcfg;
    vcfg.base_directory      = "var/uml001/audit.vault";
    vcfg.max_file_size_bytes = 64ULL * 1024 * 1024;
    vcfg.max_file_age_seconds = 86400;
    vcfg.fsync_on_write      = true;

    auto vault_backend = std::make_unique<SimpleFileVaultBackend>(
        vcfg.base_directory);
    ColdVault vault(vcfg, std::move(vault_backend), os_clock, hash_provider);

    // =========================================================================
    // Step 1 — Obtain daemon public key [L-5]
    // =========================================================================
    std::string daemon_pubkey;
    try {
        daemon_pubkey = read_daemon_pubkey();
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }

    // =========================================================================
    // Step 2 — Configure BftClockClient
    // =========================================================================
    BftClockClientConfig clock_cfg;
    clock_cfg.daemon_pubkey_hex = daemon_pubkey;
    clock_cfg.client_id         = "uml001-app";
    clock_cfg.socket_path       = read_socket_path();
    clock_cfg.max_skew_s        = IPC_MAX_SKEW_S;
    clock_cfg.cache_ttl_ms      = IPC_CACHE_TTL_MS;
    clock_cfg.fail_closed       = true;

    const char* hmac_env = std::getenv("UML001_BFT_IPC_HMAC_KEY");
    if (hmac_env && std::strlen(hmac_env) == 64)
        clock_cfg.ipc_hmac_key_hex = std::string(hmac_env);

#ifndef UML001_TEST_CLOCK

    auto bft_client = std::make_shared<BftClockClient>(clock_cfg);

    // =========================================================================
    // Step 3 — Liveness check (SEC-003)
    // =========================================================================
    {
        std::cout << "[CLOCK INIT] Contacting BFT clock daemon at "
                  << clock_cfg.socket_path << "...\n";
        uint64_t t = 0;
        try {
            t = bft_client->now_unix();
        } catch (const SecurityViolation& sv) {
            std::cerr << "[FATAL] Clock security verification failed:\n"
                      << "  " << sv.what() << "\n";
            return 1;
        } catch (const BftClockIpcError& ie) {
            std::cerr << "[FATAL] Cannot connect to BFT clock daemon:\n"
                      << "  " << ie.what() << "\n"
                      << "  Is uml001-bft-clockd running? "
                      << "  Check UML001_BFT_SOCKET (default: "
                      << clock_cfg.socket_path << ")\n";
            return 1;
        }

        std::cout << "[CLOCK INIT] BFT time=" << t
                  << " issued_at="     << bft_client->last_issued_at()
                  << " uncertainty_s=" << bft_client->last_uncertainty_s()
                  << "\n";

        // [E-7] CLOCK_INIT vault entry with full provenance
        vault.log_security_event(
            "CLOCK_INIT",
            "agreed_time=" + std::to_string(t) +
            " unc=" + std::to_string(bft_client->last_uncertainty_s()) +
            " iat=" + std::to_string(bft_client->last_issued_at()));
    }

    // =========================================================================
    // Step 4 — Register as global IClock
    // =========================================================================
    init_clock(bft_client);

    const BftClockClient& clock_ref = *bft_client;

#else // UML001_TEST_CLOCK ---------------------------------------------------

    auto mock = std::make_shared<MockClock>();
    mock->set_test_time(1'740'000'000ULL);
    init_clock(mock);
    std::cout << "[TEST MODE] MockClock pinned at " << mock->now_unix() << "\n";

    // In test mode, vault_append_with_provenance is not available.
    // Use vault.log_security_event() directly below.

#endif // UML001_TEST_CLOCK

    // =========================================================================
    // Step 5 — PassportRegistry
    // =========================================================================
    PassportRegistry registry(ROOT_KEY, REG_VERSION, get_clock());

    // =========================================================================
    // SECTION 1 — Passport issuance
    // =========================================================================
    Capabilities caps_full;
    caps_full.classifier_authority   = true;
    caps_full.classifier_sensitivity = true;
    caps_full.bft_consensus          = true;
    caps_full.entropy_flush          = true;

    Capabilities caps_auth_only;
    caps_auth_only.classifier_authority   = true;
    caps_auth_only.classifier_sensitivity = false;
    caps_auth_only.bft_consensus          = false;
    caps_auth_only.entropy_flush          = false;

    Capabilities caps_flush_only;
    caps_flush_only.classifier_authority   = false;
    caps_flush_only.classifier_sensitivity = false;
    caps_flush_only.bft_consensus          = false;
    caps_flush_only.entropy_flush          = true;

    const std::string policy_hash = sha256_hex("uml001-policy-v0.1.0");

    SemanticPassport pa = registry.issue(
        "agent-alpha", "1.0.0", caps_full,       policy_hash, NOW, PASSPORT_TTL_S);
    SemanticPassport pb = registry.issue(
        "agent-beta",  "1.0.0", caps_auth_only,  policy_hash, NOW, PASSPORT_TTL_S);
    SemanticPassport pc = registry.issue(
        "agent-gamma", "1.0.0", caps_flush_only, policy_hash, NOW, PASSPORT_TTL_S);

    std::cout << "[REGISTRY] Issued: "
              << pa.model_id << " " << pb.model_id << " " << pc.model_id << "\n";

    // =========================================================================
    // SECTION 2 — Passport verification
    // =========================================================================
    {
        auto vr_a = registry.verify(pa);
        auto vr_b = registry.verify(pb);
        auto vr_c = registry.verify(pc);

        std::cout << "[VERIFY] alpha=" << vr_a.status_str()
                  << " beta="          << vr_b.status_str()
                  << " gamma="         << vr_c.status_str() << "\n";

        if (!vr_a.ok())
            throw std::runtime_error("agent-alpha passport verification failed");
    }

    // =========================================================================
    // SECTION 3 — PolicyEngine
    // =========================================================================
    CompatibilityManifest compat;
    compat.expected_registry_version = REG_VERSION;
    compat.policy_hash               = policy_hash;

    std::vector<PolicyRule> rules;
    {
        PolicyRule r1;
        r1.rule_id             = "allow-low-sensitivity";
        r1.trust.min_authority_confidence   = 0.7f;
        r1.trust.min_sensitivity_confidence = 0.7f;
        r1.scope.authority_min   = 0.5f;
        r1.scope.sensitivity_max = 0.3f;
        r1.action                = PolicyAction::ALLOW;
        rules.push_back(r1);

        PolicyRule r2;
        r2.rule_id             = "flag-mid-sensitivity";
        r2.trust.min_authority_confidence   = 0.7f;
        r2.trust.min_sensitivity_confidence = 0.7f;
        r2.scope.authority_min   = 0.5f;
        r2.scope.sensitivity_max = 0.7f;
        r2.action                = PolicyAction::FLAG;
        rules.push_back(r2);
    }

    PolicyEngine policy_engine(compat, rules, PolicyAction::DENY);

    // =========================================================================
    // SECTION 4 — Sessions with warp weights and thresholds [E-8]
    // =========================================================================
#ifndef UML001_TEST_CLOCK
    FlushCallback flush_cb = build_flush_callback(vault, bft_client.get());
#else
    FlushCallback flush_cb = build_flush_callback(vault, nullptr);
#endif

    SessionConfig weights;
    weights.warp_weight_allow      = WARP_WEIGHT_ALLOW;
    weights.warp_weight_flag       = WARP_WEIGHT_FLAG;
    weights.warp_weight_deny       = WARP_WEIGHT_DENY;
    weights.warp_suspect_thresh    = WARP_SUSPECT_THRESH;
    weights.warp_quarantine_thresh = WARP_QUARANTINE_THRESH;

    Session session_alpha("sess-alpha", "agent-alpha", flush_cb, weights);
    Session session_beta ("sess-beta",  "agent-beta",  flush_cb, weights);
    session_alpha.activate();
    session_beta.activate();

    std::cout << "[SESSION] alpha=" << state_str(session_alpha.state())
              << " beta="           << state_str(session_beta.state()) << "\n";

    // =========================================================================
    // SECTION 5 — Handshake
    // =========================================================================
    {
        const uint64_t nc_ttl = 300;
        const std::size_t nc_max = 10000;

        NonceCache nc_a_init(nc_ttl, nc_max);
        NonceCache nc_a_resp(nc_ttl, nc_max);

        const std::string schema = "uml001-v1";
        const uint64_t    expiry = NOW + 300;

        HandshakeValidator hv_a_init(registry, pa, schema, "tls:alpha:init",
                                     nc_a_init, expiry, false, true);
        HandshakeValidator hv_a_resp(registry, pa, schema, "tls:alpha:resp",
                                     nc_a_resp, expiry, false, true);

        auto hello     = hv_a_init.build_hello();
        auto challenge = hv_a_resp.handle_hello(hello);
        auto confirm   = hv_a_init.handle_challenge(challenge);
        auto ctx       = hv_a_resp.handle_confirm(confirm);

        if (!ctx.has_value())
            throw std::runtime_error("[HANDSHAKE] alpha failed");

        std::cout << "[HANDSHAKE] alpha established"
                  << " forward_secrecy=" << ctx->forward_secrecy
                  << " transport="       << ctx->transport_id << "\n";

        validate_timestamp(ctx->established_at);
    }

    {
        const uint64_t nc_ttl = 300;
        const std::size_t nc_max = 10000;

        NonceCache nc_b_init(nc_ttl, nc_max);
        NonceCache nc_b_resp(nc_ttl, nc_max);

        const std::string schema = "uml001-v1";
        const uint64_t    expiry = NOW + 300;

        HandshakeValidator hv_b_init(registry, pb, schema, "tls:beta:init",
                                     nc_b_init, expiry, false, false);
        HandshakeValidator hv_b_resp(registry, pb, schema, "tls:beta:resp",
                                     nc_b_resp, expiry, false, false);

        auto hello     = hv_b_init.build_hello();
        auto challenge = hv_b_resp.handle_hello(hello);
        auto confirm   = hv_b_init.handle_challenge(challenge);
        auto ctx       = hv_b_resp.handle_confirm(confirm);

        if (!ctx.has_value())
            throw std::runtime_error("[HANDSHAKE] beta failed");

        std::cout << "[HANDSHAKE] beta established"
                  << " forward_secrecy=" << ctx->forward_secrecy << "\n";

        validate_timestamp(ctx->established_at);
    }

    // =========================================================================
    // SECTION 6 — Policy evaluation [E-3]
    // =========================================================================
    {
        SemanticScore s_allow;
        s_allow.authority              = 0.85f;
        s_allow.sensitivity            = 0.15f;
        s_allow.authority_confidence   = 0.90f;
        s_allow.sensitivity_confidence = 0.88f;
        s_allow.payload_hash           = sha256_hex("payload-allow-001");
        s_allow.scored_at              = NOW;

        SemanticScore s_flag;
        s_flag.authority              = 0.75f;
        s_flag.sensitivity            = 0.55f;
        s_flag.authority_confidence   = 0.80f;
        s_flag.sensitivity_confidence = 0.78f;
        s_flag.payload_hash           = sha256_hex("payload-flag-001");
        s_flag.scored_at              = NOW;

        SemanticScore s_deny_risk;
        s_deny_risk.authority              = 0.60f;
        s_deny_risk.sensitivity            = 0.90f;
        s_deny_risk.authority_confidence   = 0.72f;
        s_deny_risk.sensitivity_confidence = 0.71f;
        s_deny_risk.payload_hash           = sha256_hex("payload-deny-risk-001");
        s_deny_risk.scored_at              = NOW;

        SemanticScore s_deny_conf;
        s_deny_conf.authority              = 0.60f;
        s_deny_conf.sensitivity            = 0.20f;
        s_deny_conf.authority_confidence   = 0.40f;
        s_deny_conf.sensitivity_confidence = 0.35f;
        s_deny_conf.payload_hash           = sha256_hex("payload-deny-conf-001");
        s_deny_conf.scored_at              = NOW;

        auto d_allow  = policy_engine.evaluate(s_allow,     REG_VERSION, &pa, RECOVERED_CONF_FLOOR);
        auto d_flag   = policy_engine.evaluate(s_flag,      REG_VERSION, &pa, RECOVERED_CONF_FLOOR);
        auto d_deny_r = policy_engine.evaluate(s_deny_risk, REG_VERSION, &pa, RECOVERED_CONF_FLOOR);
        auto d_deny_c = policy_engine.evaluate(s_deny_conf, REG_VERSION, &pa, RECOVERED_CONF_FLOOR);

        std::cout << "[POLICY] allow="  << action_str(d_allow.action)
                  << " flag="           << action_str(d_flag.action)
                  << " deny_risk="      << action_str(d_deny_r.action)
                  << " deny_conf="      << action_str(d_deny_c.action) << "\n";

        session_alpha.process_decision(d_allow);
        session_alpha.process_decision(d_flag);
        session_alpha.process_decision(d_deny_r);
        session_alpha.process_decision(d_deny_c);

        std::cout << "[SESSION alpha] warp=" << session_alpha.warp_score()
                  << " state=" << state_str(session_alpha.state()) << "\n";

#ifndef UML001_TEST_CLOCK
        // [E-3] Vault all four decisions with timestamp provenance
        vault_append_with_provenance(vault, "POLICY_DECISION",
            "sess-alpha", "agent-alpha", s_allow.payload_hash,
            "action=" + std::string(action_str(d_allow.action))
            + " rule=" + d_allow.matched_rule_id, clock_ref);

        vault_append_with_provenance(vault, "POLICY_DECISION",
            "sess-alpha", "agent-alpha", s_flag.payload_hash,
            "action=" + std::string(action_str(d_flag.action))
            + " rule=" + d_flag.matched_rule_id, clock_ref);

        vault_append_with_provenance(vault, "POLICY_DECISION_DENY",
            "sess-alpha", "agent-alpha", s_deny_risk.payload_hash,
            "action=" + std::string(action_str(d_deny_r.action))
            + " reason=high_sensitivity", clock_ref);

        vault_append_with_provenance(vault, "POLICY_DECISION_DENY",
            "sess-alpha", "agent-alpha", s_deny_conf.payload_hash,
            "action=" + std::string(action_str(d_deny_c.action))
            + " reason=low_confidence", clock_ref);
#endif
    }

    // =========================================================================
    // SECTION 7 — Drive to QUARANTINE → flush → reactivate [E-4]
    // =========================================================================
    {
        SemanticScore s;
        s.authority              = 0.20f;
        s.sensitivity            = 0.90f;
        s.authority_confidence   = 0.80f;
        s.sensitivity_confidence = 0.80f;
        s.payload_hash           = sha256_hex("payload-quarantine-trigger");
        s.scored_at              = NOW;

        auto d = policy_engine.evaluate(s, REG_VERSION, &pa, RECOVERED_CONF_FLOOR);

        for (int i = 0; i < 3; ++i) {
            session_alpha.process_decision(d);
#ifndef UML001_TEST_CLOCK
            vault_append_with_provenance(vault, "POLICY_DECISION_DENY",
                "sess-alpha", "agent-alpha", s.payload_hash,
                "action=" + std::string(action_str(d.action))
                + " quarantine_drive_seq=" + std::to_string(i)
                + " warp_after=" + std::to_string(session_alpha.warp_score()),
                clock_ref);
#endif
        }

        std::cout << "[SESSION alpha] warp=" << session_alpha.warp_score()
                  << " state=" << state_str(session_alpha.state()) << "\n";

        if (session_alpha.state() == SessionState::FLUSHING) {
#ifndef UML001_TEST_CLOCK
            vault_append_with_provenance(vault, "SESSION_QUARANTINE_FLUSH",
                "sess-alpha", "agent-alpha", sha256_hex("flush-initiated"),
                "state=FLUSHING warp=" + std::to_string(session_alpha.warp_score()),
                clock_ref);
#endif
            session_alpha.complete_flush();

#ifndef UML001_TEST_CLOCK
            vault_append_with_provenance(vault, "SESSION_FLUSH_COMPLETE",
                "sess-alpha", "agent-alpha", sha256_hex("flush-complete"),
                "state=" + std::string(state_str(session_alpha.state())),
                clock_ref);
#endif
            session_alpha.reactivate();

#ifndef UML001_TEST_CLOCK
            vault_append_with_provenance(vault, "SESSION_REACTIVATED",
                "sess-alpha", "agent-alpha", sha256_hex("reactivated"),
                "state=" + std::string(state_str(session_alpha.state())),
                clock_ref);
#endif
            std::cout << "[SESSION alpha] reactivated: "
                      << state_str(session_alpha.state()) << "\n";
        }
    }

    // =========================================================================
    // SECTION 8 — Key rotation [E-1]
    // =========================================================================
    {
        auto [new_pub, new_priv] = ed25519_keygen();
        uint32_t new_key_id = registry.rotate_key(new_pub, new_priv, NOW);

        std::cout << "[KEY ROTATE] new key_id=" << new_key_id << "\n";

#ifndef UML001_TEST_CLOCK
        vault_append_with_provenance(vault, "KEY_ROTATION",
            "system", "system",
            sha256_hex("key-rotation-" + std::to_string(new_key_id)),
            "new_key_id=" + std::to_string(new_key_id),
            clock_ref);
#endif

        auto vr = registry.verify(pa);
        std::cout << "[VERIFY POST-ROTATE] alpha=" << vr.status_str() << "\n";
    }

    // =========================================================================
    // SECTION 9 — Revocation [E-2]
    // =========================================================================
    {
        auto rev_token = registry.revoke("agent-beta", "1.0.0",
                                         "key-compromise", NOW);

        std::cout << "[REVOKE] agent-beta v1.0.0 token="
                  << rev_token.substr(0, 16) << "...\n";

#ifndef UML001_TEST_CLOCK
        vault_append_with_provenance(vault, "REVOCATION",
            "system", "agent-beta",
            sha256_hex("revocation-agent-beta-1.0.0"),
            "model=agent-beta version=1.0.0 reason=key-compromise"
            " token_prefix=" + rev_token.substr(0, 16),
            clock_ref);
#endif

        auto vr = registry.verify(pb);
        std::cout << "[VERIFY POST-REVOKE] beta=" << vr.status_str() << "\n";
    }

    // =========================================================================
    // SECTION 10 — Multi-party passport issuance [E-6]
    // =========================================================================
    {
        MultiPartyIssuer issuer(registry, 2, 3, 3600);

        auto prop = issuer.propose("agent-delta", "1.0.0",
                                    caps_full, policy_hash,
                                    NOW, PASSPORT_TTL_S,
                                    "operator-001");

        // Per-operator HMAC keys — INTEGRATION TEST VALUES ONLY [L-3]
        const std::string op002_key = sha256_hex("operator-002-hmac-key");
        const std::string op003_key = sha256_hex("operator-003-hmac-key");

        // [E-6] Token = HMAC-SHA256(operator_key, proposal_id||"|"||NOW)
        const std::string hmac_input = prop.proposal_id + "|" + std::to_string(NOW);
        const std::string token_op002 = hmac_sha256_hex(hmac_input, op002_key);
        const std::string token_op003 = hmac_sha256_hex(hmac_input, op003_key);

        issuer.countersign(prop, "operator-002", token_op002);
        issuer.countersign(prop, "operator-003", token_op003);

        auto qp = issuer.finalize(prop);
        if (qp.has_value()) {
            auto vr = registry.verify(*qp);
            std::cout << "[MULTI-PARTY] agent-delta quorum passport: "
                      << vr.status_str() << "\n";
        }
    }

    // =========================================================================
    // SECTION 11 — Recovery token issuance [E-5]
    // =========================================================================
    {
        std::string incident_id = make_incident_id("sess-alpha", vault);
        std::cout << "[RECOVERY] incident=" << incident_id << "\n";

        SemanticPassport pa_rec =
            registry.issue_recovery_token(pa, incident_id, NOW, 3600);

        auto vr_rec = registry.verify(pa_rec);
        std::cout << "[VERIFY RECOVERY] " << vr_rec.status_str() << "\n";

        SemanticScore s_border;
        s_border.authority              = 0.80f;
        s_border.sensitivity            = 0.10f;
        s_border.authority_confidence   = 0.80f;
        s_border.sensitivity_confidence = 0.80f;
        s_border.payload_hash           = sha256_hex("payload-recovered-borderline");
        s_border.scored_at              = NOW;

        auto d_border = policy_engine.evaluate(
            s_border, REG_VERSION, &pa_rec, RECOVERED_CONF_FLOOR);

        std::cout << "[POLICY RECOVERY] borderline for recovered agent: "
                  << action_str(d_border.action)
                  << " (expected DENY — conf 0.80 < floor "
                  << RECOVERED_CONF_FLOOR << ")\n";

#ifndef UML001_TEST_CLOCK
        vault_append_with_provenance(vault, "RECOVERY_TOKEN_ISSUED",
            "sess-alpha", pa.model_id,
            sha256_hex(incident_id),
            "incident=" + incident_id
            + " conf_floor=" + std::to_string(RECOVERED_CONF_FLOOR),
            clock_ref);
#endif
    }

    // =========================================================================
    // SECTION 12 — Transparency log query
    // =========================================================================
    {
        auto& tlog    = registry.transparency_log();
        auto  history = tlog.history_for("agent-alpha");

        std::cout << "[TLOG] agent-alpha events: " << history.size() << "\n";
        for (const auto& e : history)
            std::cout << "  [" << e.sequence_num << "] "
                      << e.event_type << " ts=" << e.ts << "\n";

        std::cout << "[TLOG] chain="
                  << (tlog.verify_chain() ? "VALID" : "BROKEN") << "\n";
    }

    // =========================================================================
    // SECTION 13 — Shutdown
    // =========================================================================
    std::cout << "[MAIN] Shutting down...\n";
    session_alpha.close();
    session_beta.close();
    std::cout << "[MAIN] Done.\n";

    return 0;
}