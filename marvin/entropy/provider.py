"""QuantumEntropyProvider — simulated quantum-inspired randomness.

IMPORTANT: This is *simulated* entropy. It uses Python's standard ``random``
(seedable for deterministic tests) and is NOT a certified random source and NOT
quantum hardware. The ``entropy_source`` field always declares the simulation
clearly. The class is deliberately small so it can be swapped for a real QRNG
API (e.g. an HTTP client) without touching the rest of MARVIN.
"""

from __future__ import annotations

import random
from typing import Optional, Protocol

from ..domain.models import EntropyPacket, utc_now

SIMULATED_SOURCE_LABEL = "SIMULATED_QUANTUM_INSPIRED"


class EntropyProvider(Protocol):
    """Interface a real QRNG backend would implement to replace the simulator."""

    def get_entropy(self, num_bytes: int = 32) -> EntropyPacket: ...

    def random_rotation_interval(self, low: int, high: int) -> int: ...

    def nonce(self, num_bytes: int = 12) -> bytes: ...


class QuantumEntropyProvider:
    """Simulated entropy source producing :class:`EntropyPacket` material."""

    def __init__(self, seed: Optional[int] = None) -> None:
        # A dedicated RNG keeps entropy generation independent and reproducible.
        self._rng = random.Random(seed)
        self.source_label = SIMULATED_SOURCE_LABEL

    def get_entropy(self, num_bytes: int = 32) -> EntropyPacket:
        """Return a packet of simulated entropy bytes (hex-encoded)."""
        raw = bytes(self._rng.getrandbits(8) for _ in range(num_bytes))
        return EntropyPacket(
            entropy_hex=raw.hex(),
            entropy_source=self.source_label,
            confidence_score=self._simulated_confidence(),
            generated_at=utc_now(),
        )

    def random_rotation_interval(self, low: int, high: int) -> int:
        """Jitter a policy's rotation interval to model moving-target defense."""
        if high <= low:
            return low
        return self._rng.randint(low, high)

    def nonce(self, num_bytes: int = 12) -> bytes:
        """Generate simulated nonce material."""
        return bytes(self._rng.getrandbits(8) for _ in range(num_bytes))

    def _simulated_confidence(self) -> float:
        """A simulated 'quantum confidence' score in the 0.80..0.99 band."""
        return round(self._rng.uniform(0.80, 0.99), 4)
