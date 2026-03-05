Aegis Protocol (aegis-protocol) is a high-performance C++ security layer designed to establish cryptographic identity, trust, and accountability in autonomous AI agent ecosystems. By combining Semantic Passports with a zero-trust communication protocol and a semantically-aware policy engine, aegis-protocol ensures autonomous models interact within strictly defined safety bounds, produce Byzantine-fault-tolerant consensus across agent fleets, and leave a tamper-evident audit trail. It is implemented as twelve composable C++ modules (Rev 1.2) with a companion Python SDK, addressing the complete agent security lifecycle:

**Identity Layer:**        - PassportRegistry  - KeyRotation  - RevocationList  - MultiPartyIssuer

**Communication Layer:**   - HandshakeValidator  - TransportIdentity  - NonceCache

**Intelligence Layer:**    - SemanticClassifier  - PolicyEngine  - BFTConsensusEngine

**Operational Layer:**     - Session state machine  - ColdAuditVault  - TransparencyLog  - IncidentManager

All time-dependent authorization decisions are bound to a trusted, injected IClock abstraction (resolving SEC-003), preventing attackers from manipulating authorization windows via timestamp injection. Caller-supplied timestamps are accepted only for audit log metadata.

**Core Capabilities**

* Semantic Identity: Implements Semantic Passports (v0.2) that encode a model_id, version, TTL, policy hash, and a four-flag Capabilities bitmap (classifier_authority, classifier_sensitivity, bft_consensus, entropy_flush) into an HMAC-SHA256 signed credential, enforcing least-privilege at the identity layer.
* Zero-Trust Handshaking: A robust three-message handshake (Rev 1.2) featuring ephemeral Diffie-Hellman forward secrecy, partitioned nonce caches (SEC-002) for per-party replay prevention, transport-identity binding (TLS_CERT_FINGERPRINT / TCP_ADDRESS), and directional session sub-keys to prevent impersonation and message-direction confusion attacks.
* Context-Aware Policy Engine: A real-time engine that evaluates Semantic Scores (Authority −1.0 → +1.0 vs. Sensitivity 0.0 → 1.0) against configurable TrustCriteria confidence thresholds and ScopeCriteria ranges to ALLOW, FLAG, or DENY agent actions, with a fail-closed default and elevated confidence floors for recovered agents.
* Collective Resilience: A BFT Consensus Engine aggregates multi-agent semantic scores and filters outliers using Weiszfeld geometric median with f = floor((n-1)/3) Byzantine fault tolerance, ensuring a compromised minority cannot manipulate fleet-wide decisions.
* Behavioral Anomaly Detection: A Session state machine (INIT → ACTIVE → SUSPECT → QUARANTINE → FLUSHING → RESYNC → CLOSED) accumulates a real-valued warp score across policy decisions and fires an operator-supplied entropy flush callback - delivering session_id, incident_id, and tainted payload hashes - when cumulative anomaly pressure breaches threshold.
* Tamper-Evident Accountability: Hash-chained ColdAuditVault and TransparencyLog create an immutable, cryptographically verifiable record of every policy decision, session state change, key rotation, and multi-party issuance event. verify_chain() validates the complete chain in O(n).
* Full Key and Credential Lifecycle: Key material follows ACTIVE → ROTATING → RETIRED → PURGED with configurable overlap windows. Version-scoped revocation invalidates a specific model version without disrupting the fleet. MultiPartyIssuer enforces N-of-M quorum issuance with rejection and TTL-based expiry for high-value agents.

**Intended Use**

This framework is intended for developers building multi-agent systems, AI orchestrators, or agentic platforms where cryptographic accountability, semantic policy enforcement, and post-incident forensic auditability are mission-critical. It serves as the security layer that sits between raw model inference and external action execution, and is designed to compose beneath existing orchestration frameworks (LangChain, AutoGen, OpenAI Agents SDK) without replacing them. Compile the reference integration with: g++ -std=c++17 -O2 e2e-example.cpp -lssl -lcrypto -o e2e-example

**Standards alignment:** NIST AI RMF 1.0 (MEASURE / GOVERN), NIST SP 800-53 Rev 5 (IA / AC / AU / IR / SC), NIST SP 800-218A, DoD Zero Trust Reference Architecture v2.0, OWASP LLM Top 10 v2025 (LLM01 / LLM05 / LLM08), ISA/IEC 62443-3-3, NERC CIP-007/010. License: Apache 2.0.
