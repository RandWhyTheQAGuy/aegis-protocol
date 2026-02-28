"""
aegis_protocol.crypto_utils
-------------------
Cryptographic primitives: SHA-256 hashing, HMAC-based MAC, and simple
ECDH-style ephemeral key exchange simulation.
"""

import hashlib
import hmac as _hmac
import secrets
import time
from typing import Tuple


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key, message) -> str:
    if isinstance(key, str):
        key = key.encode()
    if isinstance(message, str):
        message = message.encode()
    return _hmac.new(key, message, hashlib.sha256).hexdigest()


def generate_nonce(byte_length: int = 32) -> str:
    return secrets.token_hex(byte_length)


def derive_direction_key(session_key_hex: str, direction: str) -> str:
    try:
        material = bytes.fromhex(session_key_hex)
    except ValueError:
        material = session_key_hex.encode()
    return hmac_sha256(material, direction.encode() if isinstance(direction, str) else direction)


def ephemeral_dh_exchange() -> Tuple[str, str]:
    private_key = secrets.token_hex(32)
    public_key = sha256_hex("pub:" + private_key)
    return public_key, private_key


def compute_shared_secret(private_key_hex: str, peer_public_key_hex: str) -> str:
    """
    Symmetric shared-secret simulation.
    Both parties arrive at the same value by sorting their public keys.
    """
    own_pub = sha256_hex("pub:" + private_key_hex)
    keys = sorted([own_pub, peer_public_key_hex])
    return sha256_hex(keys[0] + keys[1])


class IClock:
    def now_unix(self) -> int:
        raise NotImplementedError


class RealWorldClock(IClock):
    def now_unix(self) -> int:
        return int(time.time())


class TestClock(IClock):
    def __init__(self, fixed_time: int = 1_740_000_000):
        self._time = fixed_time

    def set_time(self, t: int) -> None:
        self._time = t

    def now_unix(self) -> int:
        return self._time


MAX_CLOCK_SKEW_SECONDS: int = 30


def validate_timestamp(caller_ts: int, clock=None) -> None:
    from aegis_protocol.exceptions import SecurityViolation
    if clock is None:
        clock = RealWorldClock()
    auth_now = clock.now_unix()
    if (caller_ts > auth_now + MAX_CLOCK_SKEW_SECONDS or
            caller_ts < auth_now - MAX_CLOCK_SKEW_SECONDS):
        raise SecurityViolation(
            f"Timestamp out of allowed skew window: caller={caller_ts} "
            f"authoritative={auth_now} max_skew={MAX_CLOCK_SKEW_SECONDS}"
        )
