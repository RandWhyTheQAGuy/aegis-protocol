# UML-001 Key Management Policy
## Aegis Protocol

---

## 1. Key Types

### 1.1 Ed25519 Keys (Primary Trust Root)
- Used for signing BFT time responses
- Format: hex-encoded
  - Public: 32 bytes (64 hex chars)
  - Private: 64 bytes (128 hex chars)

### 1.2 HMAC Keys (Authority Authentication)
- Used for NTP authority validation
- Stored in registry: authority_id | key_id

### 1.3 AES-256-GCM Keys
- Used for internal encryption (vault, IPC extensions)

---

## 2. Key Storage Requirements

### MUST:
- Store private keys in:
  - HSM OR
  - OS-protected memory + encrypted disk

### MUST NOT:
- Store plaintext private keys in config files
- Log keys under any condition

---

## 3. In-Memory Handling

All key material MUST:

- Use `secure_zero()` before deallocation
- Avoid copies (pass by reference where possible)
- Never be stored in std::string for long-lived secrets

---

## 4. Key Identification

All keys MUST have:

- key_id (string, e.g. "v1", "2026-01")
- authority_id (for HMAC)

Composite identifier:
authority_id | key_id


---

## 5. Trust Model

Clients trust:

- A configured set of Ed25519 public keys
- Matching key_id from responses

Verification rule:

(response.key_id → lookup pubkey → verify signature)

---

## 6. Key Distribution

Public keys must be distributed via:

- Signed config bundles OR
- Secure control plane (TLS + mTLS)

---

## 7. Compromise Handling

On suspected compromise:

1. Revoke key_id immediately
2. Remove from trusted set
3. Rotate to new key
4. Invalidate cached responses

---

## 8. Compliance

Aligned with:
- NIST SP 800-57 (Key Management)
- FIPS 140-3 (Crypto Modules)
- OWASP ASVS V7
