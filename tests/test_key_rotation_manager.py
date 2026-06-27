"""Tests for the simulated key rotation manager."""

from __future__ import annotations

from marvin.domain.enums import CryptoPolicyName, EncryptionFamily, KeyStatus
from marvin.domain.models import CryptoPolicyDecision
from marvin.entropy.provider import QuantumEntropyProvider
from marvin.keys.key_rotation_manager import KeyRotationManager


def make_policy(
    name: CryptoPolicyName = CryptoPolicyName.STANDARD_AES_256_GCM,
    rekey: bool = False,
    quarantine: bool = False,
    interval: int = 3600,
) -> CryptoPolicyDecision:
    return CryptoPolicyDecision(
        policy_name=name,
        encryption_family=EncryptionFamily.AES_GCM,
        key_rotation_interval_seconds=interval,
        requires_reauthentication=False,
        requires_session_rekey=rekey,
        requires_quarantine=quarantine,
        rationale=["test"],
        compliance_notes="test",
        expected_latency_impact="LOW",
    )


def test_initial_key_is_created_and_active():
    mgr = KeyRotationManager("s")
    entropy = QuantumEntropyProvider(seed=1).get_entropy()
    event = mgr.evaluate(make_policy(), entropy)
    assert event.rotated is True
    assert mgr.active_key is not None
    assert mgr.active_key.status is KeyStatus.ACTIVE
    assert mgr.active_key.lineage_parent_key_id is None


def test_rotation_creates_new_active_key_with_lineage():
    mgr = KeyRotationManager("s")
    provider = QuantumEntropyProvider(seed=1)
    mgr.evaluate(make_policy(), provider.get_entropy())
    first = mgr.active_key
    assert first is not None

    # Force a rekey via policy.
    event = mgr.evaluate(make_policy(rekey=True), provider.get_entropy())
    assert event.rotated is True
    assert mgr.active_key is not None
    assert mgr.active_key.key_id != first.key_id
    assert mgr.active_key.status is KeyStatus.ACTIVE
    assert mgr.active_key.lineage_parent_key_id == first.key_id
    assert first.status is KeyStatus.ROTATED


def test_policy_change_triggers_rotation():
    mgr = KeyRotationManager("s")
    provider = QuantumEntropyProvider(seed=1)
    mgr.evaluate(make_policy(CryptoPolicyName.STANDARD_AES_256_GCM), provider.get_entropy())
    event = mgr.evaluate(
        make_policy(CryptoPolicyName.HYBRID_POST_QUANTUM_MODE), provider.get_entropy()
    )
    assert event.rotated is True
    assert "Policy changed" in event.reason


def test_valid_key_is_not_rotated():
    mgr = KeyRotationManager("s")
    provider = QuantumEntropyProvider(seed=1)
    mgr.evaluate(make_policy(), provider.get_entropy())
    event = mgr.evaluate(make_policy(), provider.get_entropy())
    assert event.rotated is False


def test_expired_key_is_rotated():
    mgr = KeyRotationManager("s")
    provider = QuantumEntropyProvider(seed=1)
    mgr.evaluate(make_policy(), provider.get_entropy())
    mgr.expire_active_key()
    event = mgr.evaluate(make_policy(), provider.get_entropy())
    assert event.rotated is True
    assert "expired" in event.reason.lower()


def test_quarantine_invalidates_active_key():
    mgr = KeyRotationManager("s")
    provider = QuantumEntropyProvider(seed=1)
    mgr.evaluate(make_policy(), provider.get_entropy())
    event = mgr.evaluate(make_policy(quarantine=True), provider.get_entropy())
    assert event.quarantined is True
    assert mgr.active_key is None
    # The retired key is recorded as invalidated in history.
    assert any(k.status is KeyStatus.INVALIDATED for k in mgr.history)
