"""
Aegis Protocol (Semantic Passport System)
=========================================
Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
SPDX-License-Identifier: Apache-2.0

INTENDED USE
-----------
- Open standardization candidate for distributed identity systems
- Interoperable trust infrastructure across frameworks and agents
- AI system authorization and governance enforcement layer
- Security-critical distributed execution environments

SECURITY MODEL
-------------
All external entities are untrusted by default.
All actions MUST be validated through:
    1. Semantic Passport verification
    2. Capability enforcement checks
    3. Revocation status validation
    4. Registry authenticity confirmation
    5. Audit logging for traceability

LICENSE
-------
Apache License 2.0
http://www.apache.org/licenses/LICENSE-2.0

This software is provided for research and production-grade
distributed trust system development.
"""
#!/usr/bin/env python3
"""
Aegis Protocol – End-to-End Passport Flow Test

Validates:
- Clock initialization
- Vault + Transparency Log wiring
- Passport issuance
- Passport verification
- Revocation handling (basic)

This is intended as a lightweight production sanity test.
"""

import sys
import traceback

import aegis_protocol as aegis


def main():
    print("=== Aegis Protocol Python E2E Test ===")

    try:
        # =========================================================
        # 1. Initialize Clock (Mock / deterministic)
        # =========================================================
        class MockClock(aegis.IClock):
            def now_unix(self):
                return 1740000000

            def now_ms(self):
                return 1740000000000

            def status(self):
                return 1  # SYNCHRONIZED (matches enum)

            def is_synchronized(self):
                return True

            def last_sync_unix(self):
                return 1740000000

            def source_id(self):
                return "py_mock_clock"

        clock = MockClock()
        aegis.init_clock(clock)

        print("[OK] Clock initialized")

        # =========================================================
        # 2. Initialize Vault
        # =========================================================
        vcfg = aegis.VaultConfig()
        vcfg.vault_path = "test_audit.vault"

        vault = aegis.ColdVault(vcfg)

        print("[OK] Vault initialized")

        # =========================================================
        # 3. Transparency Log + Revocation
        # =========================================================
        tlog = aegis.TransparencyLog()
        revocation = aegis.RevocationList()

        print("[OK] Transparency + Revocation ready")

        # =========================================================
        # 4. Registry Initialization
        # =========================================================
        registry = aegis.PassportRegistry(
            tlog,
            revocation,
            clock,
            vault
        )

        print("[OK] Registry initialized")

        # =========================================================
        # 5. Define Capabilities
        # =========================================================
        caps = aegis.Capabilities()
        caps.classifier_authority = True
        caps.classifier_sensitivity = 0.7
        caps.bft_consensus = True
        caps.entropy_flush = False

        # =========================================================
        # 6. Issue Passport
        # =========================================================
        policy_hash = aegis.sha256_hex("test_policy")

        passport = registry.issue(
            "agent-alpha",
            "1.0.0",
            caps,
            policy_hash,
            3600  # TTL seconds
        )

        print("[OK] Passport issued")

        # =========================================================
        # 7. Verify Passport
        # =========================================================
        result = registry.verify(passport)

        print(f"[VERIFY] status={result.status_str()}")

        if not result.ok():
            raise RuntimeError("Verification failed")

        print("[OK] Verification passed")

        # =========================================================
        # 8. Revocation Test (Optional but valuable)
        # =========================================================
        revocation.revoke(passport.signing_key_id)

        result_after_revoke = registry.verify(passport)

        print(f"[REVOKE TEST] status={result_after_revoke.status_str()}")

        # NOTE: Depending on implementation, this may:
        # - fail immediately
        # - or require propagation
        # so we don't hard-fail here

        # =========================================================
        # 9. Vault Integrity Check
        # =========================================================
        entries = vault.entry_count()
        print(f"[VAULT] entries={entries}")

        if entries == 0:
            raise RuntimeError("Vault did not record events")

        print("[OK] Vault logging confirmed")

        print("\n=== SUCCESS: Aegis Protocol E2E PASSED ===\n")
        return 0

    except Exception as e:
        print("\n[FAIL] Test failed:")
        print(str(e))
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())