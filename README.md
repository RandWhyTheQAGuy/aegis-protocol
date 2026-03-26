### Enabling safe, compliant, and verifiable agent autonomy in environments where correctness is non-negotiable.

**Aegis Protocol (aegis-protocol)** is a high-performance C++ security framework for establishing cryptographic identity, trust, and accountability in autonomous AI agent ecosystems.

By combining **Semantic Passports**, a **zero-trust communication model**, and a **semantically-aware policy engine**, Aegis Protocol ensures that autonomous systems:

- operate within strictly defined safety and authorization boundaries  
- produce verifiable, deterministic decisions  
- maintain a tamper-evident audit trail of all actions  

The system is implemented as composable C++ modules with a companion Python SDK, covering the full agent security lifecycle:

---

## 🧩 Architecture Overview

### Identity Layer
- `PassportRegistry`
- `KeyRotation`
- `RevocationList`
- `MultiPartyIssuer`

### Communication Layer
- `HandshakeValidator`
- `TransportIdentity`
- `NonceCache`

### Intelligence Layer
- `SemanticClassifier`
- `PolicyEngine`
- `BFTConsensusEngine`

### Operational Layer
- Session State Machine
- `ColdAuditVault`
- `TransparencyLog`
- `IncidentManager`

---

## ⏱ Trusted Time Model

All time-dependent authorization decisions are bound to a trusted, injected `IClock` abstraction.

- Prevents timestamp injection attacks  
- Eliminates reliance on caller-controlled time  
- Ensures consistent, verifiable authorization windows  

Caller-supplied timestamps are accepted **only for audit metadata**, never for enforcement.

---

## 🔐 Core Capabilities

### Semantic Identity
Implements **Semantic Passports (v1.0)** — cryptographically signed identity credentials containing:

- `model_id`, `version`
- TTL (time-bounded validity)
- `policy_hash`
- Capability bitmap:
  - `classifier_authority`
  - `classifier_sensitivity`
  - `bft_consensus`
  - `entropy_flush`

All passports are signed via **HMAC-SHA256**, enforcing least-privilege at the identity layer.

---

### Zero-Trust Handshaking
A hardened three-message handshake providing:

- Ephemeral Diffie-Hellman forward secrecy  
- Replay protection via partitioned nonce caches  
- Transport identity binding (TLS fingerprint / address)  
- Directional session key separation  

---

### Context-Aware Policy Engine
Evaluates actions in real time using:

- **Semantic Score:** Authority (−1.0 → +1.0) vs Sensitivity (0.0 → 1.0)  
- Configurable confidence thresholds  
- Scope-aware policy enforcement  

Outputs deterministic decisions:
- `ALLOW`
- `FLAG`
- `DENY` (fail-closed by default)

---

### Collective Resilience (BFT)
A Byzantine Fault Tolerant consensus layer:

- Uses geometric median aggregation (Weiszfeld method)  
- Tolerates up to `f = floor((n-1)/3)` compromised agents  
- Prevents adversarial manipulation of group decisions  

---

### Behavioral Anomaly Detection
Session lifecycle:
INIT → ACTIVE → SUSPECT → QUARANTINE → FLUSHING → RESYNC → CLOSED

- Tracks anomaly accumulation via a warp score  
- Triggers entropy flush callbacks on threshold breach  
- Provides structured incident context (`session_id`, `incident_id`, payload hashes)

---

### Tamper-Evident Accountability
- `ColdAuditVault`: hash-chained audit ledger  
- `TransparencyLog`: append-only governance log  

All events are:
- cryptographically linked  
- verifiable via `verify_chain()`  
- resistant to tampering  

---

### Full Credential Lifecycle
Key and identity lifecycle:
ACTIVE → ROTATING → RETIRED → PURGED


Features:
- Version-scoped revocation  
- TTL-bound credentials  
- N-of-M quorum issuance for high-value identities  

---

## 🚀 Intended Use

### Aegis Protocol is designed for:

- Multi-agent AI systems  
- Autonomous orchestration platforms  
- Safety-critical AI deployments  
- Regulated or compliance-heavy environments  

### It acts as a **security enforcement layer** between:
> model inference → real-world action

### It is designed to integrate beneath existing frameworks such as:
- LangChain  
- AutoGen  
- OpenAI Agents SDK  

---

## 🛠 Build Instructions

### Clean build (recommended)

rm -rf build
mkdir build && cd build
cmake ..
make -j8

### Minimal standalone compile (reference entry point)
g++ -std=c++17 -O2 src/main_aegis_protocol.cpp -lssl -lcrypto -o aegis_daemon

---

## 📏 Standards Alignment

Aegis Protocol aligns with:

NIST AI RMF 1.0 (MEASURE / GOVERN)
NIST SP 800-53 Rev. 5 (IA / AC / AU / IR / SC)
NIST SP 800-218A (Secure Software Development)
DoD Zero Trust Architecture v2.0
OWASP LLM Top 10 (2025)
ISA/IEC 62443-3-3
NERC CIP-007 / CIP-010

---

## 📜 License

Licensed under the Apache License, Version 2.0.

---

## ⚠️ Status

v1.0.0 — Initial Release

### This release establishes:

Semantic Passport identity model
Policy enforcement framework
Audit and transparency infrastructure

### Future versions will expand:

interoperability
SDK coverage
production integrations