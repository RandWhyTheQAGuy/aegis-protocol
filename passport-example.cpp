// example_full.cpp
// UML-001 rev 1.1 — end-to-end example exercising all four new capabilities:
//   1. Key rotation
//   2. Transparency log
//   3. Multi-party issuance
//   4. Revocation channel
//
// Compile:
//   g++ -std=c++17 -DUML001_FULL_FEATURES example_full.cpp -lssl -lcrypto -o example_full

#define UML001_FULL_FEATURES
#include "passport.h"
#include "key_rotation.h"
#include "transparency_log.h"
#include "multi_party_issuance.h"
#include "revocation.h"
#include <iostream>
#include <cassert>

int main() {
    uint64_t now = 1_740_000_000ULL;  // arbitrary base timestamp

    // =========================================================================
    // 1. TRANSPARENCY LOG — created first; everything else references it
    // =========================================================================
    std::string log_signing_key = "log-signing-key-32-bytes-padding!";
    TransparencyLog tlog(log_signing_key);

    // =========================================================================
    // 2. KEY STORE + ROTATION
    // =========================================================================
    KeyStore store;
    store.set_rotation_window(3600);  // 1-hour overlap

    KeyVersion kv1;
    kv1.key_id       = "k-2026-001";
    kv1.key_material = "initial-registry-key-32-bytes!!!";
    kv1.state        = KeyState::ACTIVE;
    kv1.activated_at = now;
    store.add_key(kv1);

    // Announce rotation: new key k-2026-002 takes over, old key retires in 1h
    RotationCoordinator rotator(store);
    KeyVersion kv2;
    kv2.key_id       = "k-2026-002";
    kv2.key_material = "rotated-registry-key-32-bytes!!!!";
    kv2.activated_at = now;
    std::string new_key_id = rotator.announce_rotation(kv2, now,
        /*retire_after=*/3600, /*purge_after=*/86400);

    std::cout << "[KEY ROTATION] New active key: " << new_key_id << "\n";
    tlog.append(TLEventType::KEY_ROTATED, new_key_id,
        "{\"retiring\":\"k-2026-001\",\"successor\":\"k-2026-002\"}", now);

    // Advance time past rotation window; old key becomes RETIRED
    store.tick(now + 4000);
    auto retired = store.keys_in_state(KeyState::RETIRED);
    std::cout << "[KEY ROTATION] Retired keys: " << retired.size() << "\n";
    assert(retired.size() == 1 && retired[0] == "k-2026-001");

    // =========================================================================
    // 3. REVOCATION CHANNEL
    // =========================================================================
    RevocationChannel revocation(
        store.active_key().key_material,
        "0.1.0",
        tlog
    );

    // Revoke a compromised agent
    revocation.revoke("agent-compromised-001",
                      RevocationReason::COMPROMISED,
                      now,
                      "INCIDENT-2026-0042");
    assert(revocation.is_revoked("agent-compromised-001"));
    std::cout << "[REVOCATION] agent-compromised-001 revoked. "
              << "List version: " << revocation.list_version() << "\n";

    // Rescind an erroneous revocation
    revocation.rescind("agent-compromised-001",
                       "false positive — wrong model_id in incident report",
                       now + 600);
    assert(!revocation.is_revoked("agent-compromised-001"));
    std::cout << "[REVOCATION] Rescinded. Still revoked? "
              << revocation.is_revoked("agent-compromised-001") << "\n";

    // Publish revocation list for gossip
    RevocationList published = revocation.publish(now + 600);
    assert(published.verify(store.active_key().key_material));
    std::cout << "[REVOCATION] Published list v" << published.list_version
              << " with " << published.entries.size() << " entries\n";

    // =========================================================================
    // 4. PASSPORT REGISTRY (full-featured mode)
    // =========================================================================
    PassportRegistry registry("0.1.0", &store, &revocation, &tlog);

    // =========================================================================
    // 5. MULTI-PARTY ISSUANCE (3-of-5 quorum)
    // =========================================================================
    std::unordered_map<std::string, std::string> signers = {
        {"issuer-A", "shard-key-A-32-bytes-padding!!!"},
        {"issuer-B", "shard-key-B-32-bytes-padding!!!"},
        {"issuer-C", "shard-key-C-32-bytes-padding!!!"},
        {"issuer-D", "shard-key-D-32-bytes-padding!!!"},
        {"issuer-E", "shard-key-E-32-bytes-padding!!!"},
    };
    QuorumIssuer quorum(signers, /*threshold=*/3, tlog);

    IssuanceRequest req;
    req.model_id        = "agent-planner-001";
    req.model_version   = "1.0.0";
    req.registry_version = "0.1.0";
    req.capabilities    = {true, true, false, true};
    req.policy_hash     = sha256_hex("default-policy-v1");
    req.issued_at       = now;
    req.expires_at      = now + 86400;

    // Three of five issuers submit shares
    for (const std::string& signer_id : {"issuer-A", "issuer-C", "issuer-E"}) {
        IssuanceShare share;
        share.signer_id    = signer_id;
        share.request_hash = req.request_hash();
        share.partial_sig  = hmac_sha256_hex(
            signers.at(signer_id), share.request_hash);
        share.signed_at    = now;
        bool accepted = quorum.submit_share(req, share, now);
        std::cout << "[QUORUM] Share from " << signer_id
                  << ": " << (accepted ? "accepted" : "rejected") << "\n";
    }

    assert(quorum.quorum_reached());
    SemanticPassport mpi_passport = quorum.finalize(req, now);
    std::cout << "[QUORUM] Passport finalized for "
              << mpi_passport.model_id << "\n";

    // =========================================================================
    // 6. NORMAL SINGLE-REGISTRY ISSUANCE (uses active key from store)
    // =========================================================================
    Capabilities caps{true, true, true, true};
    SemanticPassport p = registry.issue(
        "agent-executor-007", "2.1.0", caps,
        sha256_hex("policy-v2"), now);

    std::cout << "[ISSUANCE] Issued passport for " << p.model_id
              << " signed with key: " << p.key_id << "\n";

    // =========================================================================
    // 7. VERIFICATION (uses key_id to look up correct key version)
    // =========================================================================
    bool valid = registry.verify(p, now + 100);
    std::cout << "[VERIFY] Passport valid: " << valid << "\n";
    assert(valid);

    // Attempt to verify a revoked passport
    revocation.revoke("agent-executor-007",
                      RevocationReason::POLICY_VIOLATION, now + 200);
    bool revoked_valid = registry.verify(p, now + 300);
    std::cout << "[VERIFY] Revoked passport valid: " << revoked_valid << "\n";
    assert(!revoked_valid);

    // =========================================================================
    // 8. RECOVERY TOKEN issuance
    // =========================================================================
    SemanticPassport recovered = registry.issue_recovery_token(
        p, "INCIDENT-2026-0099", now + 400);
    std::cout << "[RECOVERY] Recovery token: "
              << recovered.recovery_token << "\n";
    assert(recovered.is_recovered());

    // =========================================================================
    // 9. VERIFY TRANSPARENCY LOG INTEGRITY
    // =========================================================================
    bool log_intact = tlog.verify_chain();
    std::cout << "[TLOG] Chain integrity: "
              << (log_intact ? "OK" : "COMPROMISED") << "\n";
    assert(log_intact);
    std::cout << "[TLOG] Total entries: " << tlog.size() << "\n";

    // Print log for inspection
    std::cout << "\n[TLOG] Export:\n" << tlog.export_json() << "\n";

    std::cout << "\nAll assertions passed.\n";
    return 0;
}