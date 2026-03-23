# UML-001 Canonical Payload Specification
## Aegis Protocol — BFT Trusted Time

---

## 1. Purpose

This document defines the canonical payload format used for
cryptographic signing and verification of BFT time responses.

The canonical payload ensures:
- Deterministic serialization
- Language-independent verification
- Protection against field reordering and injection attacks

---

## 2. Canonical Payload Definition

The payload is constructed as a UTF-8 string using ASCII encoding.

Fields are concatenated in strict order using the pipe (`|`) delimiter.

### Field Order (REQUIRED)

agreed_time |
lower_bound |
upper_bound |
uncertainty_s |
evidence_hash |
nonce |
issued_at

---

## 3. Serialization Rules

- All numeric fields are encoded as base-10 ASCII integers
- No padding or leading zeros
- Strings are inserted verbatim (no escaping)
- Delimiter is a single ASCII character: `|`
- No trailing delimiter

---

## 4. Example

1710000000|1709999990|1710000010|2|a3f9c...|9f2a...|1710000001

---


---

## 5. Signature Process

1. Construct canonical payload string
2. Compute SHA-256 digest of payload
3. Sign digest using Ed25519 private key
4. Encode signature as lowercase hex (128 chars)

---

## 6. Verification Process

1. Reconstruct canonical payload from received fields
2. Compute SHA-256 digest
3. Verify Ed25519 signature using trusted public key
4. Reject if verification fails

---

## 7. Security Properties

This design guarantees:

### S-1: Integrity
All critical fields are covered by the signature.

### S-2: Replay Protection
Nonce binds response to a specific request.

### S-3: Freshness
issued_at is validated against local clock.

### S-4: Auditability
evidence_hash links response to quorum transcript.

---

## 8. Forbidden Variations

The following are INVALID and MUST be rejected:

- Field reordering
- Missing fields
- Additional delimiters
- Non-decimal numeric encoding
- UTF-16 or non-ASCII encoding

---

## 9. Versioning Strategy

Future schema changes MUST:

- Append new fields at the end
- Never reorder existing fields
- Never change delimiter

---

## 10. Rationale

A string-based canonical format is chosen over JSON to:

- Eliminate parser ambiguity
- Prevent whitespace-based attacks
- Guarantee cross-language consistency

---

## 11. Reference Implementation

See:

- bft_clock_client.cpp → canonical_payload()
- crypto_utils.cpp → sha256_hex(), ed25519_sign()