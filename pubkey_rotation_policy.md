# UML-001 Key Rotation Policy
## Aegis Protocol

---

## 1. Goals

- Zero downtime rotation
- Backward compatibility
- No trust gaps

---

## 2. Rotation Model

### Dual-Key Window

At any time:

- 1 ACTIVE key (used for signing)
- 1+ ACCEPTED keys (used for verification)

---

## 3. Rotation Steps

### Step 1 — Introduce New Key
- Generate new Ed25519 keypair
- Assign new key_id (e.g. "v2")
- Distribute public key to all clients

### Step 2 — Dual Signing Phase
- Server signs responses with:
  - new key (primary)
- Clients accept:
  - old key
  - new key

### Step 3 — Cutover
- Stop using old key for signing
- Clients still accept old key temporarily

### Step 4 — Revocation
- Remove old key from client trust store

---

## 4. Client Verification Logic


if key_id not in trusted_keys:
reject response


---

## 5. Rotation Frequency

- Ed25519 keys: every 90–180 days
- HMAC keys: every 30–90 days

---

## 6. Emergency Rotation

Trigger conditions:

- Key exposure
- Signature anomaly
- Vault compromise

Procedure:

1. Immediately stop signing
2. Push new key
3. Invalidate all cached responses
4. Force client refresh

---

## 7. Audit Requirements

All rotations must log:

- old key_id
- new key_id
- timestamp
- operator / system

---

## 8. Backward Compatibility

Clients MUST:

- Support ≥2 keys simultaneously
- Reject unknown key_id

---

## 9. Future Extensions

- Key transparency log (public ledger)
- Certificate-based identity binding
