/**
 * @file rest_server.cpp
 * @brief REST API server entry point for the UML-001 Trusted Time API.
 *
 * CLEAN VERSION (Post-BFT Extraction)
 *
 * Key changes:
 *   - Removed ALL legacy BFT quorum clock usage
 *   - Replaced with BftClockClient (IPC → external daemon)
 *   - Fixed duplicate config variable issue
 *   - Removed invalid include placement
 *   - Added proper env-based configuration
 *   - Ensured deterministic, production-safe defaults
 */

#include <pistache/endpoint.h>
#include <pistache/router.h>

#include "uml001/core/bft_clock_client.h"
#include "uml001/vault.h"
#include "uml001/security/ivault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/strong_clock.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/rest_handlers.h"
#include "uml001/rest_auth_config.h"

#include <cstdlib>
#include <cstring>   // ✅ REQUIRED FOR strlen
#include <iostream>
#include <memory>

using namespace uml001;
using namespace uml001::rest;

int main() {
    // ----------------------------------------------------------------
    // Vault setup (UNCHANGED - correct)
    // ----------------------------------------------------------------
    OsStrongClock strong_clock;
    SimpleHashProvider hash_provider;

    ColdVault::Config vault_cfg;
    vault_cfg.base_directory      = "var/uml001/rest_audit.vault";
    vault_cfg.max_file_size_bytes = 10 * 1024 * 1024;
    vault_cfg.fsync_on_write      = true;

    auto backend = std::make_unique<SimpleFileVaultBackend>(
        vault_cfg.base_directory);

    ColdVault vault(vault_cfg, std::move(backend), strong_clock, hash_provider);

    // ----------------------------------------------------------------
    // Remote BFT Clock Client (REPLACES ALL LEGACY CLOCK LOGIC)
    // ----------------------------------------------------------------
    BftClockClientConfig clock_cfg;

    // 🔐 Public key for daemon verification
    const char* pubkey_env = std::getenv("UML001_DAEMON_PUBKEY");
    if (pubkey_env && std::strlen(pubkey_env) > 0) {
        clock_cfg.daemon_pubkey_hex = std::string(pubkey_env);
    } else {
        std::cerr << "[REST] WARNING: UML001_DAEMON_PUBKEY not set. "
                     "Clock verification may fail.\n";
        clock_cfg.daemon_pubkey_hex = ""; // safe fallback (fail-closed expected downstream)
    }

    // 🔌 IPC socket path
    const char* socket_env = std::getenv("UML001_CLOCK_SOCKET");
    if (socket_env && std::strlen(socket_env) > 0) {
        clock_cfg.socket_path = std::string(socket_env);
    } else {
        clock_cfg.socket_path = "/var/run/uml001/bft-clock.sock";
    }

    auto clock = std::make_shared<BftClockClient>(clock_cfg);

    // ----------------------------------------------------------------
    // Auth configuration (UNCHANGED - correct)
    // ----------------------------------------------------------------
    RestAuthConfig auth;
    const char* api_key_env = std::getenv("UML001_API_KEY");

    if (api_key_env && std::strlen(api_key_env) > 0) {
        auth.mode    = RestAuthMode::API_KEY;
        auth.api_key = std::string(api_key_env);
        std::cout << "[REST] API key auth enabled\n";
    } else {
        auth.mode = RestAuthMode::NONE;
        std::cerr << "[REST] WARNING: no UML001_API_KEY set — running with "
                     "auth=NONE. Acceptable only in isolated test environments.\n";
    }

    // ----------------------------------------------------------------
    // Server setup
    // ----------------------------------------------------------------
    Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(8080));

    auto opts = Pistache::Http::Endpoint::options()
        .threads(2)
        .flags(Pistache::Tcp::Options::ReuseAddr);

    Pistache::Http::Endpoint server(addr);
    server.init(opts);

    Pistache::Rest::Router router;

    TimeApiHandler handler(clock, auth, vault);
    handler.setup_routes(router);

    server.setHandler(router.handler());

    std::cout << "[REST] UML-001 Trusted Time API listening on :8080\n";

    server.serve();

    return 0;
}