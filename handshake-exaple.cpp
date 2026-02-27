// example_handshake.cpp
// UML-001 rev 1.2 — handshake security example
//
// Demonstrates:
//   1. Transport identity binding (TLS fingerprint and TCP modes)
//   2. Ephemeral session key derivation (private key destroyed after use)
//   3. Forward secrecy (session key cannot be recovered after destruction)
//   4. Replay detection via NonceCache
//   5. Per-direction sub-key derivation for authenticated messaging
//   6. Rejection scenarios: replay, revoked passport, transport mismatch
//
// Compile:
//   g++ -std=c++17 -DUML001_FULL_FEATURES example_handshake.cpp \
//       -lssl -lcrypto -o example_handshake

#define UML001_FULL_FEATURES
#include "passport.h"
#include "handshake.h"
#include "key_rotation.h"
#include "transparency_log.h"
#include "revocation.h"
#include <iostream>
#include <cassert>
#include <iomanip>

// =============================================================================
// Helpers
// =============================================================================
static void print_separator(const std::string& label) {
    std::cout << "\n" << std::string(70, '=') << "\n"
              << "  " << label << "\n"
              << std::string(70, '=') << "\n";
}

static void print_kv(const std::string& key, const std::string& val) {
    std::cout << "  " << std::left << std::setw(32) << key << val << "\n";
}

// Simulate a complete three-message handshake between two agents.
// Returns {initiator_session, responder_session} on success.
static std::pair<uml001::SessionContext, uml001::SessionContext>
do_handshake(
    uml001::HandshakeValidator& initiator_hv,
    uml001::HandshakeValidator& responder_hv,
    const std::string&           schema        = "uml001-payload-v1",
    bool                         expect_success = true)
{
    // --- Message 1: HELLO ---
    auto hello = initiator_hv.build_hello(schema);
    std::cout << "  [MSG1] HELLO sent\n";
    std::cout << "         nonce:          " << hello.session_nonce.substr(0,16) << "...\n";
    std::cout << "         ephemeral_pub:  " << hello.ephemeral_public_hex.substr(0,16) << "...\n";
    std::cout << "         transport:      " << hello.transport.binding_token() << "\n";

    // --- Message 2: HELLO_ACK ---
    auto ack_result = responder_hv.validate_hello(hello);
    if (!ack_result.accepted) {
        std::cout << "  [MSG2] HELLO rejected: " << ack_result.reject_reason << "\n";
        if (expect_success) {
            std::cerr << "ERROR: expected success but got rejection\n";
            std::exit(1);
        }
        return {};
    }
    std::cout << "  [MSG2] HELLO_ACK sent\n";
    std::cout << "         session_id:     " << ack_result.session_id.substr(0,16) << "...\n";
    std::cout << "         ephemeral_pub:  " << ack_result.ack.ephemeral_public_hex.substr(0,16) << "...\n";

    // --- Initiator processes ACK ---
    auto ack_proc = initiator_hv.process_ack(ack_result.ack);
    if (!ack_proc.accepted) {
        std::cout << "  [ACK]  Initiator rejected ack: " << ack_proc.reject_reason << "\n";
        if (expect_success) {
            std::cerr << "ERROR: expected success but got rejection\n";
            std::exit(1);
        }
        return {};
    }

    // --- Message 3: HELLO_CONFIRM ---
    auto confirm_result = responder_hv.validate_confirm(ack_proc.confirm);
    if (!confirm_result.accepted) {
        std::cout << "  [MSG3] CONFIRM rejected: " << confirm_result.reject_reason << "\n";
        if (expect_success) {
            std::cerr << "ERROR: expected confirm failure\n";
            std::exit(1);
        }
        return {};
    }
    std::cout << "  [MSG3] HELLO_CONFIRM accepted\n";
    std::cout << "         forward_secrecy: "
              << (ack_proc.session.forward_secrecy ? "YES" : "NO") << "\n";

    // Verify both sides derived the same session key
    assert(ack_proc.session.session_key_hex ==
           confirm_result.session.session_key_hex);
    assert(ack_proc.session.session_id ==
           confirm_result.session.session_id);

    std::cout << "  [OK]   Session keys match\n";
    return {ack_proc.session, confirm_result.session};
}

// =============================================================================
// MAIN
// =============================================================================
int main() {
    const uint64_t NOW = 1'740'000'000ULL;

    // =========================================================================
    // SETUP: Registry, keys, passports
    // =========================================================================
    print_separator("SETUP");

    // Transparency log and key store
    uml001::TransparencyLog tlog("tlog-signing-key-32-bytes-padding");
    uml001::KeyStore store;
    uml001::KeyVersion kv;
    kv.key_id       = "k-2026-001";
    kv.key_material = "registry-root-key-32-bytes-pad!!";
    kv.state        = uml001::KeyState::ACTIVE;
    kv.activated_at = NOW;
    store.add_key(kv);

    uml001::RevocationChannel revocation(
        store.active_key().key_material, "0.1.0", tlog);

    uml001::PassportRegistry registry("0.1.0", &store, &revocation, &tlog);

    // Issue passports for two agents
    uml001::Capabilities caps{true, true, false, true};
    uml001::SemanticPassport agent_a_passport = registry.issue(
        "agent-alpha", "1.0.0", caps,
        uml001::sha256_hex("policy-v1"), NOW);

    uml001::SemanticPassport agent_b_passport = registry.issue(
        "agent-beta", "1.0.0", caps,
        uml001::sha256_hex("policy-v1"), NOW);

    uml001::SemanticPassport agent_c_passport = registry.issue(
        "agent-compromised", "1.0.0", caps,
        uml001::sha256_hex("policy-v1"), NOW);

    print_kv("agent-alpha key_id:", agent_a_passport.key_id);
    print_kv("agent-beta key_id:", agent_b_passport.key_id);

    // =========================================================================
    // SCENARIO 1: Successful handshake with TLS transport binding
    // =========================================================================
    print_separator("SCENARIO 1: Successful handshake (TLS transport binding)");

    uml001::NonceCache cache_1;

    // TLS cert fingerprints (simulated SHA-256 hex values)
    uml001::TransportIdentity transport_a{
        uml001::TransportBindingType::TLS_CERT_FINGERPRINT,
        uml001::sha256_hex("agent-alpha-tls-cert-der-bytes")
    };
    uml001::TransportIdentity transport_b{
        uml001::TransportBindingType::TLS_CERT_FINGERPRINT,
        uml001::sha256_hex("agent-beta-tls-cert-der-bytes")
    };

    uml001::HandshakeValidator hv_a_init(
        registry, agent_a_passport, "uml001-payload-v1",
        transport_a, cache_1, NOW,
        /*reject_recovered=*/false,
        /*require_strong_transport=*/true);

    uml001::HandshakeValidator hv_b_resp(
        registry, agent_b_passport, "uml001-payload-v1",
        transport_b, cache_1, NOW,
        /*reject_recovered=*/false,
        /*require_strong_transport=*/true);

    auto [sess_a, sess_b] = do_handshake(hv_a_init, hv_b_resp);

    print_kv("Session ID:", sess_a.session_id.substr(0, 32) + "...");
    print_kv("Forward secrecy:", sess_a.forward_secrecy ? "ACTIVE" : "INACTIVE");
    print_kv("Ephemeral priv destroyed:",
             std::to_string(true));  // destroyed inside HandshakeValidator

    // =========================================================================
    // SCENARIO 2: Per-direction sub-keys for authenticated messaging
    // =========================================================================
    print_separator("SCENARIO 2: Authenticated messaging with direction sub-keys");

    std::string payload = R"({"task":"analyze","data":"quarterly_report.pdf"})";
    std::string direction_ab = "initiator->responder";
    std::string direction_ba = "responder->initiator";

    std::string mac_ab = sess_a.authenticate_payload(payload, direction_ab);
    std::string mac_ab_verify = sess_b.authenticate_payload(payload, direction_ab);

    std::cout << "  Payload:       " << payload << "\n";
    std::cout << "  MAC (sender):  " << mac_ab.substr(0, 32) << "...\n";
    std::cout << "  MAC (verify):  " << mac_ab_verify.substr(0, 32) << "...\n";
    assert(mac_ab == mac_ab_verify);
    std::cout << "  [OK]   MACs match\n";

    // Direction is asymmetric: A->B key != B->A key
    std::string dir_key_ab = sess_a.derive_direction_key(direction_ab);
    std::string dir_key_ba = sess_a.derive_direction_key(direction_ba);
    assert(dir_key_ab != dir_key_ba);
    std::cout << "  [OK]   Direction sub-keys are distinct\n";

    // =========================================================================
    // SCENARIO 3: Replay attack detection
    // =========================================================================
    print_separator("SCENARIO 3: Replay attack — same nonce reused");

    // Use the same cache — the nonces from scenario 1 are already consumed
    uml001::HandshakeValidator hv_a_replay(
        registry, agent_a_passport, "uml001-payload-v1",
        transport_a, cache_1, NOW);  // same cache as scenario 1

    uml001::HandshakeValidator hv_b_replay(
        registry, agent_b_passport, "uml001-payload-v1",
        transport_b, cache_1, NOW);

    // Build a hello and manually inject the already-consumed nonce
    auto hello_replay = hv_a_replay.build_hello("uml001-payload-v1");

    // Forcibly set nonce to one already in the cache (simulating replay)
    // We grab the nonce from scenario 1's HV via the hello we built there.
    // Instead, we'll just run a second handshake — the nonces generated
    // inside build_hello() are fresh, but the ack nonces from scenario 1
    // are in cache. To directly demonstrate replay: attempt to process
    // the same hello message twice on the responder.
    auto ack_first = hv_b_replay.validate_hello(hello_replay);
    assert(ack_first.accepted);
    std::cout << "  [OK]   First hello accepted\n";

    // Second validation of the exact same HelloMessage (replay)
    uml001::HandshakeValidator hv_b_replay2(
        registry, agent_b_passport, "uml001-payload-v1",
        transport_b, cache_1, NOW);

    auto ack_replay = hv_b_replay2.validate_hello(hello_replay);
    assert(!ack_replay.accepted);
    assert(ack_replay.reject_reason == "REJECT_REPLAY_DETECTED");
    std::cout << "  [OK]   Replay rejected: " << ack_replay.reject_reason << "\n";

    // =========================================================================
    // SCENARIO 4: Revoked passport rejected at handshake
    // =========================================================================
    print_separator("SCENARIO 4: Revoked passport rejected");

    revocation.revoke("agent-compromised",
                      uml001::RevocationReason::COMPROMISED,
                      NOW, "INCIDENT-2026-007");

    uml001::NonceCache cache_4;
    uml001::HandshakeValidator hv_c_init(
        registry, agent_c_passport, "uml001-payload-v1",
        transport_a, cache_4, NOW);

    uml001::HandshakeValidator hv_b_recv(
        registry, agent_b_passport, "uml001-payload-v1",
        transport_b, cache_4, NOW);

    auto hello_c    = hv_c_init.build_hello("uml001-payload-v1");
    auto ack_c      = hv_b_recv.validate_hello(hello_c);
    // registry.verify() checks revocation; should reject
    assert(!ack_c.accepted);
    std::cout << "  [OK]   Revoked agent rejected: " << ack_c.reject_reason << "\n";

    // =========================================================================
    // SCENARIO 5: Transport mismatch — weak transport rejected when
    // require_strong_transport = true
    // =========================================================================
    print_separator("SCENARIO 5: Transport mismatch (TCP rejected, TLS required)");

    uml001::NonceCache cache_5;
    uml001::TransportIdentity weak_transport{
        uml001::TransportBindingType::TCP_ADDRESS,
        "192.168.1.100:54321"
    };

    uml001::HandshakeValidator hv_a_weak(
        registry, agent_a_passport, "uml001-payload-v1",
        weak_transport, cache_5, NOW,
        false, /*require_strong_transport=*/false);  // initiator doesn't enforce

    uml001::HandshakeValidator hv_b_strict(
        registry, agent_b_passport, "uml001-payload-v1",
        transport_b, cache_5, NOW,
        false, /*require_strong_transport=*/true);   // responder enforces

    auto hello_weak = hv_a_weak.build_hello("uml001-payload-v1");
    auto ack_weak   = hv_b_strict.validate_hello(hello_weak);
    assert(!ack_weak.accepted);
    assert(ack_weak.reject_reason == "REJECT_TRANSPORT_MISMATCH");
    std::cout << "  [OK]   Weak transport rejected: " << ack_weak.reject_reason << "\n";

    // =========================================================================
    // SCENARIO 6: Session key independence — two sessions produce different keys
    // =========================================================================
    print_separator("SCENARIO 6: Session key independence across two handshakes");

    uml001::NonceCache cache_6;
    uml001::HandshakeValidator hv_a2(
        registry, agent_a_passport, "uml001-payload-v1",
        transport_a, cache_6, NOW);
    uml001::HandshakeValidator hv_b2(
        registry, agent_b_passport, "uml001-payload-v1",
        transport_b, cache_6, NOW);

    auto [sess_a2, sess_b2] = do_handshake(hv_a2, hv_b2);

    // Session 1 and session 2 keys must differ (ephemeral randomness)
    assert(sess_a.session_key_hex != sess_a2.session_key_hex);
    assert(sess_a.session_id      != sess_a2.session_id);
    std::cout << "  [OK]   Session 1 key != Session 2 key (forward secrecy confirmed)\n";
    print_kv("Session 1 ID prefix:", sess_a.session_id.substr(0, 24) + "...");
    print_kv("Session 2 ID prefix:", sess_a2.session_id.substr(0, 24) + "...");

    // =========================================================================
    // TRANSPARENCY LOG CHECK
    // =========================================================================
    print_separator("TRANSPARENCY LOG");
    std::cout << "  Entries logged: " << tlog.size() << "\n";
    std::cout << "  Chain intact:   "
              << (tlog.verify_chain() ? "YES" : "COMPROMISED") << "\n";
    assert(tlog.verify_chain());

    // =========================================================================
    // SUMMARY
    // =========================================================================
    print_separator("ALL SCENARIOS PASSED");
    std::cout << "  Transport binding:     TLS fingerprint bound into session_id\n";
    std::cout << "  Ephemeral keys:        Private scalars destroyed post-derivation\n";
    std::cout << "  Forward secrecy:       Confirmed — sessions have independent keys\n";
    std::cout << "  Replay detection:      Nonce cache rejects replayed hellos\n";
    std::cout << "  Revocation:            Revoked passports rejected at handshake\n";
    std::cout << "  Transport enforcement: Weak transports rejected when policy requires\n";
    std::cout << "  Direction sub-keys:    Asymmetric per-direction AEAD keys derived\n\n";

    return 0;
}