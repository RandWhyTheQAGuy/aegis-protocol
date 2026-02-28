**12 modules, 4 layers**

**Aegis Protocol** (aegis-protocol) is a high-performance C++ security layer designed to establish identity, trust, and accountability in decentralized AI agent ecosystems. By combining cryptographic "Semantic Passports" with a zero-trust communication protocol, aegis-protocol ensures autonomous models interact within strictly defined safety bounds and leave a tamper-evident audit trail. It implemented as multiple composable C++ modules (Rev 1.2), addressing the complete agent security lifecycle:

  Identity Layer:
    - PassportRegistry
    - KeyRotation
    - RevocationList
    - MultiPartyIssuer

  Communication Layer:
    - HandshakeValidator
    - TransportIdentity
    - NonceCache

  Intelligence Layer:
    - SemanticClassifier
    - PolicyEngine
    - BFTConsensusEngine

  Operational Layer:
    - Session state machine
    - ColdAuditVault
    - TransparencyLog
    - IncidentManager

All time-dependent authorization decisions are bound to a trusted, injected
IClock abstraction (resolving SEC-003), preventing attackers from manipulating
authorization windows via timestamp injection. Caller-supplied timestamps are
accepted only for audit log metadata.

### Core Capabilities

* **Semantic Identity:** Implements **Semantic Passports** (v0.2) that encode model capabilities and policy hashes into a cryptographically signed identity.
* **Zero-Trust Handshaking:** A robust three-way handshake (Rev 1.2) featuring transport-identity binding, ephemeral session keys, and forward secrecy to prevent replay and impersonation attacks.
* **Context-Aware Policy Engine:** A real-time engine that evaluates **Semantic Scores** (Authority vs. Sensitivity) against trust criteria to permit, flag, or deny agent actions.
* **Tamper-Evident Accountability:** Uses hash-chained **Audit Vaults** and **Transparency Logs** to create an immutable record of every decision, session state change, and key rotation.
* **Collective Resilience:** Includes a **BFT Consensus Engine** to aggregate multi-agent scores and filter outliers using geometric median-based fault tolerance.

### Intended Use

This framework is intended for developers building multi-agent systems, AI orchestrators, or "Agentic" platforms where safety, verifiable identity, and post-incident forensic auditability are mission-critical. It serves as the "security layer" that sits between raw model inference and external action execution.
