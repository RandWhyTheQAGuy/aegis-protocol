"""
aegis_protocol.clock
~~~~~~~~~~~~
Trusted clock abstraction.

Resolves SEC-003 (CRITICAL): all authorization time checks are bound to the
authoritative clock returned by IClock.now_unix().  Caller-supplied timestamps
are validated against a ±MAX_CLOCK_SKEW_SECONDS window and accepted only for
audit-log metadata, never for authorization decisions.
"""

import time
from abc import ABC, abstractmethod

from .exceptions import ClockSkewError

MAX_CLOCK_SKEW_SECONDS: int = 30


class IClock(ABC):
    """Abstract clock interface — inject a TestClock in unit tests."""

    @abstractmethod
    def now_unix(self) -> int:
        """Return the current time as Unix epoch seconds."""

    def validate_timestamp(self, caller_ts: int) -> None:
        """
        Assert that *caller_ts* is within MAX_CLOCK_SKEW_SECONDS of the
        authoritative clock.  Raises ClockSkewError on violation.

        Use this before accepting any caller-supplied timestamp in an
        authorization context.
        """
        auth_now = self.now_unix()
        if abs(caller_ts - auth_now) > MAX_CLOCK_SKEW_SECONDS:
            raise ClockSkewError(
                f"Timestamp out of allowed skew window: "
                f"caller={caller_ts} authoritative={auth_now} "
                f"max_skew={MAX_CLOCK_SKEW_SECONDS}"
            )


class RealWorldClock(IClock):
    """Production clock backed by time.time()."""

    def now_unix(self) -> int:
        return int(time.time())


class TestClock(IClock):
    """
    Injectable clock for unit tests.  Only available when the module is
    imported; should never be used in production code.

    Usage:
        clock = TestClock(1_740_000_000)
        registry = PassportRegistry(root_key, version, clock=clock)
        clock.advance(3600)   # move forward 1 hour
    """

    def __init__(self, initial_time: int = 1_740_000_000) -> None:
        self._time = initial_time

    def now_unix(self) -> int:
        return self._time

    def set(self, t: int) -> None:
        self._time = t

    def advance(self, seconds: int) -> None:
        self._time += seconds
