# Aegis Protocol Python SDK

A pure-Python implementation of the **Aegis Protocol Semantic Agent Security** framework,
ported from the C++ reference implementation.

## Modules

| Module | Description |
|---|---|
| `aegis_protocol.crypto_utils` | SHA-256, HMAC, nonces, ephemeral DH, trusted clock |
| `aegis_protocol.passport` | `PassportRegistry`, `SemanticPassport`, `VerifyResult`, `KeyStore` |
| `aegis_protocol.revocation` | `RevocationList` — full-model and version-scoped revocation |
| `aegis_protocol.transparency_log` | Append-only hash-chained transparency log |
| `aegis_protocol.multi_party` | `MultiPartyIssuer` — 2-of-N quorum, rejection, expiry |
| `aegis_protocol.handshake` | `HandshakeValidator` rev 1.2 — 3-message protocol, forward secrecy |
| `aegis_protocol.classifier` | `SemanticClassifier` — pluggable scoring backends |
| `aegis_protocol.policy` | `PolicyEngine` — CompatibilityManifest, TrustCriteria, ScopeCriteria |
| `aegis_protocol.session` | `Session` — INIT→ACTIVE→SUSPECT→QUARANTINE→FLUSHING→RESYNC→CLOSED |
| `aegis_protocol.consensus` | `BFTConsensusEngine` — geometric median, outlier detection |
| `aegis_protocol.vault` | `ColdAuditVault` — append-only tamper-evident chain |
| `aegis_protocol.incident` | `make_incident_id` — embedded epoch + 128-bit hash suffix |

## Quick Start

```python
from aegis_protocol import PassportRegistry, CAPS_FULL, TestClock, sha256_hex

clock = TestClock(1_740_000_000)
registry = PassportRegistry("my-32-byte-root-key-padded!!!", "0.1.0", clock)

passport = registry.issue(
    model_id="my-agent",
    version="1.0.0",
    capabilities=CAPS_FULL,
    policy_hash=sha256_hex("my-policy"),
    issued_at=clock.now_unix(),
    ttl_seconds=86400,
)
result = registry.verify(passport, clock.now_unix())
assert result.ok()
```

## Running Tests

```bash
python tests.py
# or
python -m pytest tests.py -v
```

## Security Notes

- All authorization time checks are bound to an injected `IClock` (resolves SEC-003).
- Nonce caches are partitioned per party to prevent cross-party replay (resolves SEC-002).
- Recovery tokens strip `classifier_authority`, `bft_consensus`, and `entropy_flush`
  capabilities and raise the trust confidence floor to 0.95.
