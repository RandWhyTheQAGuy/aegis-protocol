**Aegis Protocol** (aegis-protocol) is a high-performance C++ security layer designed to establish identity, trust, and accountability in decentralized AI agent ecosystems. By combining cryptographic "Semantic Passports" with a zero-trust communication protocol, aegis-protocol ensures autonomous models interact within strictly defined safety bounds and leave a tamper-evident audit trail. It implemented as multiple
composable C++ modules (Rev 1.2), addressing the complete agent security
lifecycle:

 - PassportRegistry (passport.h): Cryptographic identity issuance and
    verification for AI agents, with granular capability constraints enforced
    via a four-bit Capabilities bitmap (classifier_authority,
    classifier_sensitivity, bft_consensus, entropy_flush).

  - KeyStore / Key Rotation (key_rotation.h): Signing key lifecycle management
    with ACTIVE-to-ROTATING-to-RETIRED-to-PURGED state transitions and overlap
    windows for zero-downtime rotation.

  - RevocationList (revocation.h): Full-model and version-scoped revocation
    with cryptographically signed revocation tokens.

  - MultiPartyIssuer (multi_party_issuance.h): N-of-M threshold quorum for
    passport issuance, with rejection and TTL-based expiry.

  - HandshakeValidator (handshake.h, Rev 1.2): Three-message authenticated key
    establishment with ephemeral Diffie-Hellman, forward secrecy, partitioned
    nonce caches (SEC-002), and transport binding enforcement.

  - SemanticClassifier (classifier.h): Pluggable payload scoring producing
    authority (-1.0 to +1.0) and sensitivity (0.0 to 1.0) dimensions with
    confidence values.

  - PolicyEngine (policy.h): Rule-based policy evaluation with
    CompatibilityManifest, TrustCriteria confidence gates, ScopeCriteria
    ranges, and ALLOW/FLAG/DENY actions.

  - Session (session.h): State machine
    (INIT-ACTIVE-SUSPECT-QUARANTINE-FLUSHING-RESYNC-CLOSED) with warp score
    accumulation, entropy flush callback, and re-activation.

  - BFTConsensusEngine (consensus.h): Geometric median computation with outlier
    detection and f = floor((n-1)/3) Byzantine fault tolerance.

  - ColdAuditVault (vault.h): Append-only, SHA-256 hash-chained audit vault.

  - TransparencyLog (transparency_log.h): Hash-chained registry event log with
    per-model history.

  - Incident Management: Structured incident ID generation with embedded epoch
    and 128-bit hash suffix.

### Core Capabilities

* **Semantic Identity:** Implements **Semantic Passports** (v0.2) that encode model capabilities and policy hashes into a cryptographically signed identity.
* **Zero-Trust Handshaking:** A robust three-way handshake (Rev 1.2) featuring transport-identity binding, ephemeral session keys, and forward secrecy to prevent replay and impersonation attacks.
* **Context-Aware Policy Engine:** A real-time engine that evaluates **Semantic Scores** (Authority vs. Sensitivity) against trust criteria to permit, flag, or deny agent actions.
* **Tamper-Evident Accountability:** Uses hash-chained **Audit Vaults** and **Transparency Logs** to create an immutable record of every decision, session state change, and key rotation.
* **Collective Resilience:** Includes a **BFT Consensus Engine** to aggregate multi-agent scores and filter outliers using geometric median-based fault tolerance.

### Intended Use

This framework is intended for developers building multi-agent systems, AI orchestrators, or "Agentic" platforms where safety, verifiable identity, and post-incident forensic auditability are mission-critical. It serves as the "security layer" that sits between raw model inference and external action execution.
