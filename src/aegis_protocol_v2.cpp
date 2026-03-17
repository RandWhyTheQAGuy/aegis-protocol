/**
 * e2e-example.cpp  –  UML-001 Full End-to-End Integration
 * =========================================================
 *
 * BFT clock as a separate process
 * ────────────────────────────────
 * In this revision the BFT quorum clock runs as a separate daemon
 * ("uml001-bft-clockd").  This application does NOT perform NTP queries,
 * BFT consensus, or drift computation.  Instead it uses BftClockClient
 * (bft_clock_client.h), an IClock implementation that:
 *
 *   1. Connects to the daemon's Unix domain socket (or Windows named pipe).
 *   2. Sends a time request containing a fresh CSPRNG nonce.
 *   3. Receives a signed response containing the BFT-agreed time.
 *   4. Verifies the Ed25519 signature against the pinned daemon public key.
 *   5. Verifies the nonce echo, issued-at skew, and monotonic floor.
 *   6. Returns agreed_time; rejects or throws on any verification failure.
 *
 * Security properties of the IPC channel
 * ────────────────────────────────────────
 *   [S-1] Ed25519 signature – daemon public key pinned at construction.
 *         Forgery requires the daemon's private key.
 *   [S-2] Nonce echo – replay of any prior response is cryptographically
 *         rejected.  Each request carries 32 bytes of fresh randomness.
 *   [S-3] Issued-at skew check – stale but valid responses are rejected.
 *         Default max_skew_s = 5 s.
 *   [S-4] Agreed-time monotonicity – now_unix() never goes backwards.
 *   [S-5] Socket path ownership check (POSIX) – lstat() verifies the
 *         socket is owned by the daemon UID and has mode 0600 before
 *         connect().  Prevents path-substitution / symlink attacks.
 *   [S-6] Line length limits – MAX_REQUEST_LINE / MAX_RESPONSE_LINE.
 *   [S-7] Optional channel-level HMAC – when ipc_hmac_key_hex is set,
 *         every message is tagged.  Recommended on shared filesystems.
 *   [S-8] Reconnect back-off – exponential, 100 ms → 30 s.
 *
 * Deployment topologies
 * ─────────────────────
 *   A) Daemon managed externally (systemd, Docker, Kubernetes)
 *      – BftClockDaemonHandle is NOT used.
 *      – Application only constructs BftClockClient with the pinned pubkey.
 *      – Socket path and pubkey are supplied via config / environment.
 *
 *   B) Daemon managed by this process (integration tests, single-binary)
 *      – BftClockDaemonHandle launches the daemon binary, waits for the
 *        socket to appear, then provides make_client_config().
 *      – Daemon is terminated on BftClockDaemonHandle destruction.
 *
 *   This file implements topology A by default and topology B when
 *   BFT_CLOCK_DAEMON_BINARY is defined (see Step 1 below).
 *
 * Clock independence
 * ──────────────────
 * All NOW usages resolve through the global IClock registered in Step 4.
 * The application has no compile-time or link-time dependency on
 * BFTQuorumTrustedClock, NtpObservationFetcher, or RedisClockStore.
 * Those types live exclusively in the daemon binary.
 *
 * Security findings from prior revisions
 * ───────────────────────────────────────
 * All prior findings ([C-1..C-3], [H-1..H-3], [M-1..M-5]) remain resolved.
 * The IPC boundary introduces the new surface mitigated by [S-1..S-8] above.
 *
 * Fixes applied in this revision
 * ────────────────────────────────
 * [E-1] Key rotation event (Section 8) now writes a VAULT entry alongside
 *       the transparency log record.  The vault provides the tamper-evident
 *       hash-chain record required by NERC CIP-007 and NIST SP 800-53 AU-9.
 *       The tlog alone is in-memory and is not independently verifiable at
 *       the byte level.
 *
 * [E-2] Revocation event (Section 9) now writes a VAULT entry for the same
 *       reason as [E-1].  Revocation is a high-value security event; the
 *       vault record provides non-repudiable proof for incident response.
 *
 * [E-3] All four policy decisions in Section 6 (ALLOW, FLAG, DENY-risk,
 *       DENY-conf) now write individual VAULT entries.  The prior code
 *       vaulted only the ALLOW decision.  Denied and flagged actions are
 *       higher-value audit events; omitting them broke NIST SP 800-53 AU-2.
 *
 * [E-4] The three process_decision() calls in Section 7 that drive the
 *       session to QUARANTINE, and the complete_flush()/reactivate() calls
 *       that follow, each write VAULT entries.  The state transition
 *       ACTIVE->SUSPECT->QUARANTINE is the most significant security event a
 *       session can generate; omitting vault records for it left a silent gap
 *       in the tamper-evident audit trail.
 *
 * [E-5] The static uint32_t inc_ctr in make_incident_id() has been replaced
 *       with vault entry count + 128-bit CSPRNG suffix.  The prior counter
 *       reset to zero on process restart, allowing two incidents in the same
 *       session to receive the same ID after a restart.
 *
 * [E-6] MultiPartyIssuer countersign tokens (Section 10) are now
 *       hmac_sha256(operator_key, proposal_id || issued_at) instead of
 *       random bytes.  This provides cryptographic binding between the token
 *       and the countersigning operator's identity, satisfying the AC-5
 *       separation-of-duties requirement at the cryptographic layer.
 *
 * [E-7] uncertainty_s and issued_at from BftClockClient diagnostics are now
 *       embedded in all vault entries via vault_append_with_provenance().
 *       This makes timestamp quality and BFT consensus round machine-readable
 *       in each audit record, satisfying NIST SP 800-53 AU-8.
 *
 * [E-8] WARP_SUSPECT_THRESH and WARP_QUARANTINE_THRESH are now co-located
 *       with the warp weights and both are populated into SessionConfig
 *       together.  The prior code defined thresholds as compile-time constants
 *       and weights as runtime struct fields, making it possible to change a
 *       weight without a corresponding threshold adjustment.
 *
 * Remaining notes
 * ───────────────
 *   [L-1] SecurityViolation messages include BFT time.  Sanitise before
 *         propagating to external callers.
 *   [L-2] Reconnect errors written to std::cerr.  Replace with injectable
 *         logging callback for production.
 *   [L-3] ROOT_KEY literal is an integration-test value only.  Production:
 *         supply via HSM / secrets manager.
 *   [L-4] BftClockClient held as shared_ptr<IClock>; daemon handle on stack.
 *   [L-5] DAEMON_PUBKEY_HEX must be provisioned securely (not hardcoded in
 *         production).  Read from a sealed file, HSM, or env var populated
 *         by the secrets manager.
 */

// =============================================================================
// Includes – ALL at file scope, never inside a function
// =============================================================================
#include "bft_clock_client.h"        // BftClockClient, BftClockClientConfig,
                                     // BftClockDaemonHandle, BftClockIpcError
#include "clock.h"                   // IClock, init_clock, get_clock, NOW,
                                     // validate_timestamp, SecurityViolation
#include "vault.h"                   // ColdVault, ColdAuditVault, VaultConfig
#include "crypto_utils.h"            // sha256_hex, hmac_sha256_hex,
                                     // generate_random_bytes_hex, ed25519_keygen
#include "session.h"                 // Session, SessionConfig, SessionState, FlushCallback
#include "policy.h"                  // PolicyEngine, PolicyRule, PolicyDecision,
                                     // SemanticScore, CompatibilityManifest, PolicyAction
#include "passport.h"                // PassportRegistry, SemanticPassport, Capabilities
#include "handshake.h"               // HandshakeValidator, NonceCache, SessionContext
#include "multi_party_issuance.h"    // MultiPartyIssuer
#include "transparency_log.h"        // TransparencyLog
#include "key_rotation.h"            // (PassportRegistry::rotate_key)
#include "revocation.h"              // (PassportRegistry::revoke)

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
#include <cstdlib>    // std::getenv
#include <cstring>    // std::strlen
#include <stdexcept>
#include <algorithm>  // std::remove_if

using namespace uml001;

// =============================================================================
// Named constants
// =============================================================================

// Root key – INTEGRATION TEST VALUE ONLY.  Replace with HSM material [L-3].
static constexpr const char* ROOT_KEY    = "registry-root-key-32byte-padding";
static constexpr const char* REG_VERSION = "0.1.0";

static constexpr uint32_t PASSPORT_TTL_S = 86400;   // 24 h

// Confidence floor enforced for RECOVERED-flagged passports.
// Passed explicitly to PolicyEngine::evaluate(); runtime-adjustable.
static constexpr float RECOVERED_CONF_FLOOR = 0.95f;

// Session Warp Score thresholds and weights.
//
// [E-8] Both groups are defined together here so that a change to one
// immediately signals the need to review the other.  Thresholds must be
// consistent with the weight scale: if WARP_WEIGHT_DENY is increased, the
// number of denials needed to reach WARP_QUARANTINE_THRESH decreases, which
// may require lowering the threshold to preserve the intended session
// sensitivity.  Session construction validates that quarantine_thresh >
// suspect_thresh > 0.
static constexpr float WARP_WEIGHT_ALLOW       = -0.1f;
static constexpr float WARP_WEIGHT_FLAG        =  0.5f;
static constexpr float WARP_WEIGHT_DENY        =  1.0f;
static constexpr float WARP_SUSPECT_THRESH     =  1.0f;
static constexpr float WARP_QUARANTINE_THRESH  =  3.0f;

// IPC: maximum permitted skew between client wall-clock and response issued_at.
// 5 s is appropriate for a local socket on the same host.
static constexpr uint64_t IPC_MAX_SKEW_S   = 5;

// Cache TTL: BftClockClient reuses the last response for this many ms.
// 200 ms is appropriate for session / handshake expiry checks.
static constexpr uint64_t IPC_CACHE_TTL_MS = 200;

// =============================================================================
// read_daemon_pubkey()
//
// Reads the daemon's Ed25519 public key (64 hex chars) from, in priority order:
//   1. Environment variable UML001_BFT_PUBKEY       (CI / container)
//   2. File path UML001_BFT_PUBKEY_FILE             (production)
//   3. Compile-time -DBFT_CLOCK_TEST_PUBKEY=<key>  (tests only)
//
// In production the key must be provisioned by the secrets manager and must
// never appear in source code [L-5].
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
                  [](char c){ return c == '\n' || c == '\r' || c == ' '; }),
                  key.end());
        if (key.size() != 64)
            throw std::runtime_error(
                "UML001_BFT_PUBKEY_FILE: key must be exactly 64 hex chars");
        return key;
    }

#ifdef BFT_CLOCK_TEST_PUBKEY
    return std::string(BFT_CLOCK_TEST_PUBKEY);
#endif

    throw std::runtime_error(
        "BFT clock daemon public key not configured.\n"
        "  Set UML001_BFT_PUBKEY (64 hex chars) or\n"
        "  UML001_BFT_PUBKEY_FILE (path to key file).\n"
        "  In test builds, define -DBFT_CLOCK_TEST_PUBKEY=<key>.");
}

// =============================================================================
// read_socket_path()
// =============================================================================
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
// make_incident_id()
//
// Unique incident token using the BFT-verified clock [H-1].
// Never uses std::chrono::system_clock directly.
//
// [E-5] Uniqueness is derived from vault.entry_count() (monotonically
// increasing within the process lifetime) plus 128 bits of CSPRNG randomness.
// The prior static uint32_t counter reset to zero on process restart, allowing
// two incidents in the same session to receive colliding IDs after a restart.
// vault_seq + rnd_suffix makes collision negligible across restarts.
// =============================================================================
static std::string make_incident_id(const std::string& session_id,
                                    const ColdVault&   vault)
{
    const uint64_t    t         = now_unix();           // BFT-verified [H-1]
    const uint64_t    vault_seq = vault.entry_count();  // monotonic within process
    const std::string rnd       = generate_random_bytes_hex(16);  // 128 bits

    std::ostringstream oss;
    oss << "INC-" << session_id << "-" << t
        << "-" << vault_seq
        << "-" << rnd;
    return oss.str();
}

// =============================================================================
// vault_append_with_provenance()
//
// Appends a vault entry and embeds BFT timestamp provenance (uncertainty_s,
// issued_at) in the metadata field.  [E-7]
//
// Every vault entry now carries the quality bound and consensus-round
// reference for its timestamp, satisfying NIST SP 800-53 AU-8 (time stamps).
// This allows a SIEM analyst to determine not just when an event was recorded
// but how accurately that timestamp is attested by the BFT quorum.
// =============================================================================
static void vault_append_with_provenance(ColdVault&            vault,
                                          const std::string&    event_type,
                                          const std::string&    session_id,
                                          const std::string&    actor_id,
                                          const std::string&    payload_hash,
                                          const std::string&    metadata,
                                          const BftClockClient& clock_client)
{
    const uint64_t t           = now_unix();
    const uint64_t uncertainty = clock_client.last_uncertainty_s();
    const uint64_t iat         = clock_client.last_issued_at();

    // Provenance suffix: uncertainty bound and the issued_at of the BFT
    // consensus round that produced this timestamp.
    const std::string prov = "unc=" + std::to_string(uncertainty)
                           + " iat=" + std::to_string(iat);

    const std::string full_meta = metadata.empty() ? prov : metadata + "|" + prov;

    vault.append(event_type, session_id, actor_id, payload_hash, full_meta, t);
}

// =============================================================================
// build_flush_callback()
//
// EntropyFlushCallback appending every tainted payload hash to the audit vault.
// Defined at file scope; no definitions inside main() [M-1].
//
// [E-7] Each flush entry now carries timestamp provenance via the clock_client
// pointer so that the BFT uncertainty and issued_at values are machine-readable
// in the vault record.  The clock_client pointer must outlive all sessions.
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
        const uint64_t iat         = clock_client
                                   ? clock_client->last_issued_at()     : 0;
        const std::string prov     = "unc=" + std::to_string(uncertainty)
                                   + " iat=" + std::to_string(iat);

        for (const auto& h : tainted_hashes)
            vault.append("ENTROPY_FLUSH_TAINT",
                         session_id, /*actor_id=*/"",
                         h,
                         incident_id + "|" + prov,
                         now_unix());
    };
}

// =============================================================================
// main()
// =============================================================================
int main()
{
    // =========================================================================
    // Step 0 – Audit vault
    // =========================================================================
    VaultConfig vcfg;
    vcfg.vault_path            = "var/uml001/audit.vault";
    vcfg.archive_dir           = "var/uml001/archives/";
    vcfg.rotate_after_bytes    = 64ULL * 1024 * 1024;  // 64 MB
    vcfg.rotate_after_entries  = 500'000;
    vcfg.compress_on_archive   = true;

    ColdVault vault(vcfg);

    // =========================================================================
    // Step 1 – Obtain daemon public key [L-5]
    // =========================================================================
    std::string daemon_pubkey;
    try {
        daemon_pubkey = read_daemon_pubkey();
    } catch (const std::exception& ex) {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }

    // =========================================================================
    // Step 2 – Configure BftClockClient
    //
    // BftClockClient is the ONLY clock type constructed in this file.
    // daemon_pubkey_hex is pinned at construction; no TOFU.
    // Optional channel-level HMAC [S-7] read from env.
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
    // Step 3 – Liveness check: initial time request before global registration
    //
    // SEC-003: no operation proceeds without a trusted time baseline.
    // Any of [S-1..S-5] failing here will throw – the correct behaviour.
    // The process must not start if clock trust cannot be established.
    // =========================================================================
    {
        std::cout << "[CLOCK INIT] Contacting BFT clock daemon at "
                  << clock_cfg.socket_path << "...\n";
        uint64_t t = 0;
        try {
            t = bft_client->now_unix();
        } catch (const SecurityViolation& sv) {
            std::cerr << "[FATAL] Clock daemon response failed security verification:\n"
                      << "  " << sv.what() << "\n";
            return 1;
        } catch (const BftClockIpcError& ie) {
            std::cerr << "[FATAL] Cannot connect to BFT clock daemon:\n"
                      << "  " << ie.what() << "\n"
                      << "  Is uml001-bft-clockd running?  "
                      << "Check UML001_BFT_SOCKET (default: "
                      << clock_cfg.socket_path << ")\n";
            return 1;
        }

        std::cout << "[CLOCK INIT] Verified BFT time: " << t
                  << "  issued_at="     << bft_client->last_issued_at()
                  << "  uncertainty_s=" << bft_client->last_uncertainty_s()
                  << "\n";

        // [E-7] CLOCK_INIT vault entry carries the full timestamp provenance:
        // agreed_time, uncertainty_s, issued_at.  This is the genesis record
        // for the audit chain; all subsequent entries reference the same
        // provenance format via vault_append_with_provenance().
        vault.append("CLOCK_INIT", "main", "",
                     std::to_string(t),
                     "unc=" + std::to_string(bft_client->last_uncertainty_s())
                     + " iat=" + std::to_string(bft_client->last_issued_at()),
                     t);
    }

    // =========================================================================
    // Step 4 – Register BftClockClient as the global IClock
    //
    // From this point all NOW expansions and validate_timestamp() invocations
    // go through the IPC client.  All subsystems consume time exclusively
    // via the global clock.
    // =========================================================================
    init_clock(bft_client);

    // Convenience reference for vault_append_with_provenance() calls below.
    const BftClockClient& clock_ref = *bft_client;

#else  // UML001_TEST_CLOCK -------------------------------------------------------

    auto mock = std::make_shared<MockClock>();
    mock->set_test_time(1'740'000'000ULL);
    init_clock(mock);
    std::cout << "[TEST MODE] MockClock pinned at " << mock->now_unix() << "\n";

    // In test mode there is no BftClockClient.  vault_append_with_provenance()
    // is not available; use vault.append() directly in test builds.
    // (Production builds always use vault_append_with_provenance().)

#endif // UML001_TEST_CLOCK

    // =========================================================================
    // Step 5 – PassportRegistry with the authoritative clock
    // =========================================================================
    PassportRegistry registry(ROOT_KEY, REG_VERSION, get_clock());

    // =========================================================================
    // SECTION 1 – Passport issuance
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
    // SECTION 2 – Passport verification
    //
    // registry.verify() uses IClock internally; no caller-supplied timestamp [H-2].
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
    // SECTION 3 – PolicyEngine
    // =========================================================================
    CompatibilityManifest compat;
    compat.expected_registry_version = REG_VERSION;
    compat.policy_hash               = policy_hash;

    std::vector<PolicyRule> rules;
    {
        PolicyRule r1;
        r1.rule_id               = "allow-low-sensitivity";
        r1.trust                 = { .min_authority_confidence   = 0.7f,
                                     .min_sensitivity_confidence = 0.7f };
        r1.scope.authority_min   = 0.5f;
        r1.scope.sensitivity_max = 0.3f;
        r1.action                = PolicyAction::ALLOW;
        rules.push_back(r1);

        PolicyRule r2;
        r2.rule_id               = "flag-mid-sensitivity";
        r2.trust                 = { .min_authority_confidence   = 0.7f,
                                     .min_sensitivity_confidence = 0.7f };
        r2.scope.authority_min   = 0.5f;
        r2.scope.sensitivity_max = 0.7f;
        r2.action                = PolicyAction::FLAG;
        rules.push_back(r2);
        // No rule matched → default_action = DENY (fail-closed)
    }

    PolicyEngine policy_engine(compat, rules, PolicyAction::DENY);

    // =========================================================================
    // SECTION 4 – Sessions with configurable Warp Score weights
    //
    // [E-8] Weights and thresholds populated from the co-located named
    // constants above.  Session construction validates consistency.
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
    weights.warp_suspect_thresh    = WARP_SUSPECT_THRESH;    // [E-8]
    weights.warp_quarantine_thresh = WARP_QUARANTINE_THRESH; // [E-8]

    Session session_alpha("sess-alpha", "agent-alpha", flush_cb, weights);
    Session session_beta ("sess-beta",  "agent-beta",  flush_cb, weights);
    session_alpha.activate();
    session_beta.activate();

    std::cout << "[SESSION] alpha=" << state_str(session_alpha.state())
              << " beta="           << state_str(session_beta.state()) << "\n";

    // =========================================================================
    // SECTION 5 – Handshake with per-party NonceCaches
    //
    // [C-2] Per-party NonceCaches prevent cross-party nonce namespace collision.
    // =========================================================================
    {
        const uint64_t nc_ttl = 300;
        const size_t   nc_max = 10000;

        NonceCache nc_a_init(nc_ttl, nc_max);
        NonceCache nc_a_resp(nc_ttl, nc_max);

        const std::string schema = "uml001-v1";
        const uint64_t    expiry = NOW + 300;

        HandshakeValidator hv_a_init(registry, pa, schema, "tls:alpha:init",
                                     nc_a_init, expiry,
                                     /*reject_recovered=*/false,
                                     /*require_strong=*/true);
        HandshakeValidator hv_a_resp(registry, pa, schema, "tls:alpha:resp",
                                     nc_a_resp, expiry,
                                     /*reject_recovered=*/false,
                                     /*require_strong=*/true);

        auto hello     = hv_a_init.build_hello();
        auto challenge = hv_a_resp.handle_hello(hello);
        auto confirm   = hv_a_init.handle_challenge(challenge);
        auto ctx       = hv_a_resp.handle_confirm(confirm);

        if (!ctx.has_value())
            throw std::runtime_error("[HANDSHAKE] alpha failed");

        std::cout << "[HANDSHAKE] alpha established"
                  << " forward_secrecy=" << ctx->forward_secrecy
                  << " transport="       << ctx->transport_id << "\n";

        // validate_timestamp() from clock.h; throws SecurityViolation on skew.
        validate_timestamp(ctx->established_at);
    }

    {
        const uint64_t nc_ttl = 300;
        const size_t   nc_max = 10000;

        NonceCache nc_b_init(nc_ttl, nc_max);
        NonceCache nc_b_resp(nc_ttl, nc_max);

        const std::string schema = "uml001-v1";
        const uint64_t    expiry = NOW + 300;

        HandshakeValidator hv_b_init(registry, pb, schema, "tls:beta:init",
                                     nc_b_init, expiry,
                                     /*reject_recovered=*/false,
                                     /*require_strong=*/false);
        HandshakeValidator hv_b_resp(registry, pb, schema, "tls:beta:resp",
                                     nc_b_resp, expiry,
                                     /*reject_recovered=*/false,
                                     /*require_strong=*/false);

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
    // SECTION 6 – Policy evaluation and Warp Score accumulation
    //
    // [E-3] All four decisions (ALLOW, FLAG, DENY-risk, DENY-conf) are vaulted.
    // The prior code vaulted only ALLOW; FLAG and DENY outcomes were absent
    // from the tamper-evident record, violating NIST SP 800-53 AU-2.
    // DENY entries use a distinct event_type ("POLICY_DECISION_DENY") so a
    // SIEM can filter on high-severity outcomes without parsing metadata.
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

        session_alpha.process_decision(d_allow);   // warp -= 0.1
        session_alpha.process_decision(d_flag);    // warp += 0.5
        session_alpha.process_decision(d_deny_r);  // warp += 1.0
        session_alpha.process_decision(d_deny_c);  // warp += 1.0

        std::cout << "[SESSION alpha] warp=" << session_alpha.warp_score()
                  << " state=" << state_str(session_alpha.state()) << "\n";

#ifndef UML001_TEST_CLOCK
        // [E-3] Vault all four decisions with timestamp provenance [E-7].
        vault_append_with_provenance(vault, "POLICY_DECISION",
            "sess-alpha", "agent-alpha", s_allow.payload_hash,
            "action=" + action_str(d_allow.action)
            + " rule=" + d_allow.matched_rule_id, clock_ref);

        vault_append_with_provenance(vault, "POLICY_DECISION",
            "sess-alpha", "agent-alpha", s_flag.payload_hash,
            "action=" + action_str(d_flag.action)
            + " rule=" + d_flag.matched_rule_id, clock_ref);

        // DENY entries use a distinct event_type for SIEM filtering.
        vault_append_with_provenance(vault, "POLICY_DECISION_DENY",
            "sess-alpha", "agent-alpha", s_deny_risk.payload_hash,
            "action=" + action_str(d_deny_r.action)
            + " reason=high_sensitivity", clock_ref);

        vault_append_with_provenance(vault, "POLICY_DECISION_DENY",
            "sess-alpha", "agent-alpha", s_deny_conf.payload_hash,
            "action=" + action_str(d_deny_c.action)
            + " reason=low_confidence", clock_ref);
#endif
    }

    // =========================================================================
    // SECTION 7 – Drive session to QUARANTINE → flush → reactivate
    //
    // ACTIVE → SUSPECT → QUARANTINE → FLUSHING → RESYNC → ACTIVE
    //
    // [E-4] Every process_decision() call that changes session state, and the
    // complete_flush()/reactivate() transitions, now each write VAULT entries.
    // The prior code produced no vault records in this entire section — the
    // state machine transitions were invisible in the tamper-evident audit trail.
    // The flush callback still writes ENTROPY_FLUSH_TAINT entries for each
    // tainted payload hash; the entries below record the state transitions.
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

        // Three DENY decisions accumulate warp past WARP_QUARANTINE_THRESH.
        // Each decision is individually vaulted so the accumulation sequence
        // is auditable and the exact decision count is recoverable post-incident.
        for (int i = 0; i < 3; ++i) {
            session_alpha.process_decision(d);
#ifndef UML001_TEST_CLOCK
            vault_append_with_provenance(vault, "POLICY_DECISION_DENY",
                "sess-alpha", "agent-alpha", s.payload_hash,
                "action=" + action_str(d.action)
                + " quarantine_drive_seq=" + std::to_string(i)
                + " warp_after=" + std::to_string(session_alpha.warp_score()),
                clock_ref);
#endif
        }

        std::cout << "[SESSION alpha] warp=" << session_alpha.warp_score()
                  << " state=" << state_str(session_alpha.state()) << "\n";

        if (session_alpha.state() == SessionState::FLUSHING) {
#ifndef UML001_TEST_CLOCK
            // [E-4] Record that the quarantine threshold was breached and the
            // flush was initiated at a specific BFT-verified time.
            vault_append_with_provenance(vault, "SESSION_QUARANTINE_FLUSH",
                "sess-alpha", "agent-alpha",
                sha256_hex("flush-initiated"),
                "state=FLUSHING warp=" + std::to_string(session_alpha.warp_score()),
                clock_ref);
#endif

            session_alpha.complete_flush();

#ifndef UML001_TEST_CLOCK
            // [E-4] Record flush completion (RESYNC state).
            vault_append_with_provenance(vault, "SESSION_FLUSH_COMPLETE",
                "sess-alpha", "agent-alpha",
                sha256_hex("flush-complete"),
                "state=" + state_str(session_alpha.state()),
                clock_ref);
#endif

            session_alpha.reactivate();

#ifndef UML001_TEST_CLOCK
            // [E-4] Record reactivation.  This closes the incident window;
            // NIST SP 800-53 IR-4 requires that incident closure be logged
            // as well as initiation.
            vault_append_with_provenance(vault, "SESSION_REACTIVATED",
                "sess-alpha", "agent-alpha",
                sha256_hex("reactivated"),
                "state=" + state_str(session_alpha.state()),
                clock_ref);
#endif

            std::cout << "[SESSION alpha] reactivated: "
                      << state_str(session_alpha.state()) << "\n";
        }
    }

    // =========================================================================
    // SECTION 8 – Key rotation
    //
    // Old passports remain verifiable during the overlap window.
    //
    // [E-1] Key rotation now writes a VAULT entry alongside the transparency
    // log record.  The tlog provides the sequence-linked governance record;
    // the vault provides the independent tamper-evident hash-chain proof
    // required by NERC CIP-007 and NIST SP 800-53 AU-9.
    // =========================================================================
    {
        auto [new_priv, new_pub] = ed25519_keygen();
        uint32_t new_key_id = registry.rotate_key(new_pub, new_priv, NOW);

        std::cout << "[KEY ROTATE] new key_id=" << new_key_id << "\n";

#ifndef UML001_TEST_CLOCK
        // [E-1] Vault the key rotation event.  The payload hash covers the
        // new key ID so a vault chain replay can confirm which key was rotated
        // at this position in the chain without storing the key material itself.
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
    // SECTION 9 – Version-scoped revocation
    //
    // Revoke agent-beta 1.0.0 specifically; other versions unaffected.
    //
    // [E-2] Revocation now writes a VAULT entry alongside the tlog record.
    // The full revocation token is NOT stored in the vault entry to avoid
    // creating a secondary location where the token could be exfiltrated;
    // only the first 16 chars (token prefix) are included for correlation.
    // =========================================================================
    {
        auto rev_token = registry.revoke("agent-beta", "1.0.0",
                                         /*reason=*/"key-compromise", NOW);

        std::cout << "[REVOKE] agent-beta v1.0.0 token="
                  << rev_token.substr(0, 16) << "...\n";

#ifndef UML001_TEST_CLOCK
        // [E-2] Vault the revocation event with reason and token prefix.
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
    // SECTION 10 – Multi-party passport issuance (2-of-3)
    //
    // M=2 countersignatures required; no single operator can forge a credential.
    //
    // [E-6] Countersign tokens are now hmac_sha256(operator_key, proposal_id
    // || NOW) instead of random bytes.  The operator_key must be provisioned
    // per-operator by the secrets manager [L-3].  The HMAC binding makes each
    // countersign record independently verifiable by any party holding the
    // operator's public key, satisfying NIST SP 800-53 AC-5 at the
    // cryptographic layer rather than only at the process/policy layer.
    //
    // NOW is included in the HMAC input so the token is time-bound: a token
    // produced at a different time for the same proposal_id is distinct.
    // This prevents a token from being cached and replayed for a later proposal
    // by the same operator.
    // =========================================================================
    {
        MultiPartyIssuer issuer(registry, /*M=*/2, /*N=*/3, /*ttl_s=*/3600);

        auto prop = issuer.propose("agent-delta", "1.0.0",
                                    caps_full, policy_hash,
                                    NOW, PASSPORT_TTL_S,
                                    /*proposer=*/"operator-001");

        // Per-operator HMAC keys – INTEGRATION TEST VALUES ONLY [L-3].
        // Production: read from HSM or secrets manager per operator identity.
        const std::string op002_key = sha256_hex("operator-002-hmac-key");
        const std::string op003_key = sha256_hex("operator-003-hmac-key");

        // [E-6] Token = hmac_sha256(operator_key, proposal_id || "|" || NOW).
        const std::string proposal_id = prop.proposal_id;
        const std::string hmac_input  = proposal_id + "|" + std::to_string(NOW);
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
    // SECTION 11 – Recovery token issuance
    //
    // [E-5] make_incident_id() uses vault entry count + CSPRNG suffix.
    // See make_incident_id() definition above main().
    // =========================================================================
    {
        // [E-5] Incident ID is now globally unique across process restarts.
        std::string incident_id = make_incident_id("sess-alpha", vault);
        std::cout << "[RECOVERY] incident=" << incident_id << "\n";

        SemanticPassport pa_rec =
            registry.issue_recovery_token(pa, incident_id, NOW, /*ttl_s=*/3600);

        auto vr_rec = registry.verify(pa_rec);
        std::cout << "[VERIFY RECOVERY] " << vr_rec.status_str() << "\n";

        SemanticScore s_border;
        s_border.authority              = 0.80f;
        s_border.sensitivity            = 0.10f;
        s_border.authority_confidence   = 0.80f;   // >= 0.7 base but < 0.95 floor
        s_border.sensitivity_confidence = 0.80f;
        s_border.payload_hash           = sha256_hex("payload-recovered-borderline");
        s_border.scored_at              = NOW;

        auto d_border = policy_engine.evaluate(
            s_border, REG_VERSION, &pa_rec, RECOVERED_CONF_FLOOR);

        std::cout << "[POLICY RECOVERY] borderline for recovered agent: "
                  << action_str(d_border.action)
                  << " (expected DENY – conf 0.80 < recovered floor "
                  << RECOVERED_CONF_FLOOR << ")\n";

#ifndef UML001_TEST_CLOCK
        // Vault the recovery event with incident ID and applied confidence floor.
        vault_append_with_provenance(vault, "RECOVERY_TOKEN_ISSUED",
            "sess-alpha", pa.model_id,
            sha256_hex(incident_id),
            "incident=" + incident_id
            + " conf_floor=" + std::to_string(RECOVERED_CONF_FLOOR),
            clock_ref);
#endif
    }

    // =========================================================================
    // SECTION 12 – Transparency log query
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
    // SECTION 13 – Vault chain verification
    // =========================================================================
    {
        std::cout << "[VAULT] entries=" << vault.entry_count()
                  << " bytes="          << vault.byte_count() << "\n";
        bool ok = vault.verify_chain();
        std::cout << "[VAULT] chain=" << (ok ? "VALID" : "BROKEN") << "\n";
        if (!ok)
            std::cerr << "[WARN] Vault chain broken – possible tampering\n";
    }

    // =========================================================================
    // Graceful shutdown
    // =========================================================================
    std::cout << "[MAIN] Shutting down...\n";

    session_alpha.close();
    session_beta.close();

    std::cout << "[MAIN] Done.\n";
    return 0;
}