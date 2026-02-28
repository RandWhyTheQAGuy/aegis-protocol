"""
aegis_protocol.incident
---------------
Incident ID generation — embedded epoch + 128-bit hash suffix.
"""

import dataclasses
import time
from typing import Tuple

from aegis_protocol.crypto_utils import sha256_hex


@dataclasses.dataclass
class IncidentId:
    id:    str
    epoch: int


def make_incident_id(incident_ref: str, clock=None) -> IncidentId:
    """
    Returns an IncidentId with an embedded epoch and 128-bit hash suffix.

    Parameters
    ----------
    incident_ref:
        Human-readable reference string, e.g. ``"2026-042"``.
    clock:
        Optional IClock for deterministic tests.
    """
    if clock is not None:
        epoch = clock.now_unix()
    else:
        epoch = int(time.time())

    preimage = f"{incident_ref}:{epoch}"
    h = sha256_hex(preimage)
    incident_id = f"INCIDENT-{incident_ref}-{epoch}-{h[:32]}"
    return IncidentId(id=incident_id, epoch=epoch)
