"""KeyRotationManager — simulate the lifecycle of session keys.

This is the *Rotate Keys* stage. Keys are *simulated*: a key is just an
identifier with metadata (no real key material is used for encryption). The
manager creates keys from entropy packets, expires them, rotates on policy
change or interval, tracks lineage (parent → child), and can invalidate a
session entirely (quarantine).
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Optional

from ..domain.enums import KeyStatus
from ..domain.models import (
    CryptoPolicyDecision,
    EntropyPacket,
    KeyRotationEvent,
    SessionKey,
    utc_now,
)


class KeyRotationManager:
    """Manage simulated :class:`SessionKey` state for a single session."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._active_key: Optional[SessionKey] = None
        self._history: list[SessionKey] = []

    @property
    def active_key(self) -> Optional[SessionKey]:
        return self._active_key

    @property
    def history(self) -> list[SessionKey]:
        """All keys ever created for the session, in creation order."""
        return list(self._history)

    def _new_key(
        self, policy: CryptoPolicyDecision, entropy: EntropyPacket, parent_id: Optional[str]
    ) -> SessionKey:
        created = utc_now()
        interval = policy.key_rotation_interval_seconds or 3600
        key = SessionKey(
            key_id=f"key-{uuid.uuid4().hex[:12]}",
            session_id=self.session_id,
            created_at=created,
            expires_at=created + timedelta(seconds=interval),
            policy_name=policy.policy_name,
            # Reference (not the full secret) ties a key to its entropy source.
            entropy_reference=entropy.entropy_hex[:16],
            status=KeyStatus.ACTIVE,
            lineage_parent_key_id=parent_id,
        )
        self._active_key = key
        self._history.append(key)
        return key

    def ensure_initial_key(
        self, policy: CryptoPolicyDecision, entropy: EntropyPacket
    ) -> KeyRotationEvent:
        """Create the first key for a session if none exists yet."""
        if self._active_key is not None:
            return KeyRotationEvent(rotated=False, reason="Key already established.")
        key = self._new_key(policy, entropy, parent_id=None)
        return KeyRotationEvent(
            rotated=True, reason="Initial session key established.", new_key=key
        )

    def evaluate(
        self,
        policy: CryptoPolicyDecision,
        entropy: EntropyPacket,
        force_rekey: bool = False,
    ) -> KeyRotationEvent:
        """Decide whether to rotate, quarantine, or keep the current key.

        Rotation triggers, in priority order:
          1. Quarantine policy → invalidate session.
          2. No active key → establish initial key.
          3. Policy requested an explicit rekey, or ``force_rekey``.
          4. Active key's policy differs from the selected policy.
          5. Active key has expired.
        """
        if policy.requires_quarantine:
            return self._quarantine()

        if self._active_key is None:
            return self.ensure_initial_key(policy, entropy)

        current = self._active_key
        now = utc_now()

        if force_rekey or policy.requires_session_rekey:
            return self._rotate(policy, entropy, reason="Policy requires session rekey.")

        if current.policy_name != policy.policy_name:
            return self._rotate(
                policy,
                entropy,
                reason=(
                    f"Policy changed {current.policy_name.value} → "
                    f"{policy.policy_name.value}."
                ),
            )

        if now >= current.expires_at:
            return self._rotate(policy, entropy, reason="Active key expired.")

        return KeyRotationEvent(
            rotated=False, reason="Active key still valid under current policy."
        )

    def _rotate(
        self, policy: CryptoPolicyDecision, entropy: EntropyPacket, reason: str
    ) -> KeyRotationEvent:
        retired = self._active_key
        retired_id = retired.key_id if retired else None
        if retired is not None:
            retired.status = KeyStatus.ROTATED
        new_key = self._new_key(policy, entropy, parent_id=retired_id)
        return KeyRotationEvent(
            rotated=True,
            reason=reason,
            new_key=new_key,
            retired_key_id=retired_id,
        )

    def _quarantine(self) -> KeyRotationEvent:
        retired_id = None
        if self._active_key is not None:
            retired_id = self._active_key.key_id
            self._active_key.status = KeyStatus.INVALIDATED
            self._active_key = None
        return KeyRotationEvent(
            rotated=False,
            reason="Session quarantined: active key invalidated.",
            retired_key_id=retired_id,
            quarantined=True,
        )

    def expire_active_key(self) -> None:
        """Mark the active key as expired (utility for tests / manual control)."""
        if self._active_key is not None:
            self._active_key.expires_at = utc_now() - timedelta(seconds=1)
