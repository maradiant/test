"""Tests for the simulated quantum entropy provider."""

from __future__ import annotations

from marvin.entropy.provider import (
    SIMULATED_SOURCE_LABEL,
    QuantumEntropyProvider,
)


def test_entropy_packet_is_labelled_simulated():
    provider = QuantumEntropyProvider(seed=1)
    packet = provider.get_entropy()
    assert packet.entropy_source == SIMULATED_SOURCE_LABEL
    assert 0.0 <= packet.confidence_score <= 1.0
    assert len(packet.entropy_hex) == 64  # 32 bytes hex-encoded


def test_entropy_is_seed_reproducible():
    a = QuantumEntropyProvider(seed=7)
    b = QuantumEntropyProvider(seed=7)
    assert a.get_entropy().entropy_hex == b.get_entropy().entropy_hex
    assert a.nonce() == b.nonce()


def test_distinct_seeds_diverge():
    a = QuantumEntropyProvider(seed=1).get_entropy().entropy_hex
    b = QuantumEntropyProvider(seed=2).get_entropy().entropy_hex
    assert a != b


def test_rotation_interval_within_bounds():
    provider = QuantumEntropyProvider(seed=3)
    for _ in range(50):
        value = provider.random_rotation_interval(30, 300)
        assert 30 <= value <= 300


def test_nonce_length():
    provider = QuantumEntropyProvider(seed=3)
    assert len(provider.nonce(12)) == 12
    assert len(provider.nonce(16)) == 16
