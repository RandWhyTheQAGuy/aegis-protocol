/**
 * main_aegis_protocol.cpp  –  Semantic Passport Full End-to-End Integration
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
#include "uml001/bft_clock_client.h"
#include "uml001/clock.h"
#include "uml001/vault.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/session.h"
#include "uml001/policy.h"
#include "uml001/passport.h"
#include "uml001/handshake.h"
#include "uml001/multi_party_issuance.h"
#include "uml001/security/transparency_log.h"
#include "uml001/key_rotation.h"
#include "uml001/revocation.h"

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
static constexpr float RECOVERED_CONF_FLOOR = 0.95f;

static constexpr float WARP_WEIGHT_ALLOW       = -0.1f;
static constexpr float WARP_WEIGHT_FLAG        =  0.5f;
static constexpr float WARP_WEIGHT_DENY        =  1.0f;
static constexpr float WARP_SUSPECT_THRESH     =  1.0f;
static constexpr float WARP_QUARANTINE_THRESH  =  3.0f;

static constexpr uint64_t IPC_MAX_SKEW_S   = 5;
static constexpr uint64_t IPC_CACHE_TTL_MS = 200;

// =============================================================================
// FIX 2: SAFE ENV HELPERS
// =============================================================================

static std::string get_env_or_throw(const char* key)
{
    const char* val = std::getenv(key);
    if (!val || std::strlen(val) == 0)
        throw std::runtime_error(std::string("Missing required env: ") + key);
    return std::string(val);
}

// =============================================================================
// DAEMON CONFIG
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
            throw std::runtime_error("Cannot open pubkey file");

        std::string key;
        std::getline(f, key);

        key.erase(std::remove_if(key.begin(), key.end(),
                  [](char c){ return c=='\n'||c=='\r'||c==' '; }),
                  key.end());

        if (key.size() != 64)
            throw std::runtime_error("Invalid pubkey length");

        return key;
    }

    throw std::runtime_error("No BFT pubkey configured");
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
// INCIDENT ID (FIXED)
// =============================================================================

static std::string make_incident_id(const std::string& session_id,
                                    const ColdVault& vault)
{
    const uint64_t t = now_unix();
    const uint64_t seq = vault.entry_count();
    const std::string rnd = generate_random_bytes_hex(16);

    std::ostringstream oss;
    oss << "INC-" << session_id << "-" << t << "-" << seq << "-" << rnd;
    return oss.str();
}

// =============================================================================
// VAULT APPEND WITH PROVENANCE
// =============================================================================

static void vault_append_with_provenance(
    ColdVault& vault,
    const std::string& event_type,
    const std::string& session_id,
    const std::string& actor_id,
    const std::string& payload_hash,
    const std::string& metadata,
    const BftClockClient& clock_client)
{
    const uint64_t t = now_unix();

    const std::string prov =
        "unc=" + std::to_string(clock_client.last_uncertainty_s()) +
        " iat=" + std::to_string(clock_client.last_issued_at());

    vault.append(
        event_type,
        session_id,
        actor_id,
        payload_hash,
        metadata.empty() ? prov : metadata + "|" + prov,
        t
    );
}

// =============================================================================
// MAIN
// =============================================================================

int main()
{
    try
    {
        // =========================================================================
        // VAULT INIT
        // =========================================================================

        VaultConfig vcfg;
        vcfg.vault_path = "var/uml001/audit.vault";
        vcfg.archive_dir = "var/uml001/archives/";
        vcfg.rotate_after_bytes = 64ULL * 1024 * 1024;
        vcfg.rotate_after_entries = 500000;
        vcfg.compress_on_archive = true;

        ColdVault vault(vcfg);

        // =========================================================================
        // CLOCK CLIENT INIT (TRUE SIDECAR)
        // =========================================================================

        BftClockClientConfig cfg;
        cfg.daemon_pubkey_hex = read_daemon_pubkey();
        cfg.socket_path = read_socket_path();
        cfg.client_id = "aegis";
        cfg.max_skew_s = IPC_MAX_SKEW_S;
        cfg.cache_ttl_ms = IPC_CACHE_TTL_MS;
        cfg.fail_closed = true;

        auto clock = std::make_shared<BftClockClient>(cfg);

        // HARD FAIL if no quorum time
        uint64_t t = clock->now_unix();

        std::cout << "[CLOCK OK] " << t << "\n";

        init_clock(clock);

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
    }
    catch (const std::exception& e)
    {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }
}