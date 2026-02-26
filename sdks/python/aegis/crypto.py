"""
aegis.crypto
~~~~~~~~~~~~
Cryptographic utilities: SHA-256, HMAC-SHA256, and secure nonce generation.
All cryptographic operations in the SDK flow through this module.
"""

import hashlib
import hmac
import os
import secrets
from typing import Union


def sha256_hex(data: Union[str, bytes]) -> str:
    """Return the SHA-256 hex digest of *data*.

    Args:
        data: String (UTF-8 encoded) or bytes to hash.

    Returns:
        64-character lowercase hex string.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: Union[str, bytes], data: Union[str, bytes]) -> str:
    """Return the HMAC-SHA256 hex digest of *data* using *key*.

    Uses ``hmac.compare_digest`` semantics internally. Callers performing
    verification should use :func:`hmac_verify` to avoid timing attacks.

    Args:
        key:  Secret key. String (UTF-8 encoded) or bytes.
        data: Message to authenticate.

    Returns:
        64-character lowercase hex string.
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key: Union[str, bytes], data: Union[str, bytes], expected: str) -> bool:
    """Constant-time HMAC-SHA256 verification.

    Args:
        key:      Secret key.
        data:     Message that was authenticated.
        expected: Hex digest to verify against.

    Returns:
        True if the computed digest matches *expected*; False otherwise.
    """
    computed = hmac_sha256_hex(key, data)
    return hmac.compare_digest(computed, expected.lower())


def generate_nonce(byte_length: int = 32) -> str:
    """Generate a cryptographically secure random hex nonce.

    Uses :mod:`secrets` (backed by the OS CSPRNG) rather than
    :mod:`random`, which is not suitable for security-sensitive use.

    Args:
        byte_length: Number of random bytes. Default 32 → 64 hex chars.

    Returns:
        Lowercase hex string of length ``byte_length * 2``.
    """
    return secrets.token_hex(byte_length)


def canonical_sort(data: dict) -> str:
    """Produce a deterministic string representation of *data* for signing.

    Keys are sorted lexicographically. Values are coerced to strings.
    Nested dicts are flattened with dot notation. This is a lightweight
    alternative to full JSON canonicalization (RFC 8785) suitable for
    the Passport and Registry signing use cases.

    Args:
        data: Dictionary to serialize.

    Returns:
        Ampersand-delimited ``key=value`` string with keys in sorted order.

    Example::

        >>> canonical_sort({"b": 2, "a": 1})
        'a=1&b=2'
    """
    def _flatten(obj: dict, prefix: str = "") -> dict:
        items: dict = {}
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.update(_flatten(v, full_key))
            elif isinstance(v, bool):
                items[full_key] = str(v).lower()
            elif v is None:
                items[full_key] = ""
            else:
                items[full_key] = str(v)
        return items

    flat = _flatten(data)
    return "&".join(f"{k}={v}" for k, v in sorted(flat.items()))
