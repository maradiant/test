"""AuditLogger — a complete, replayable trace of MARVIN's reasoning.

This is the *Log Decision* stage. Every orchestration tick produces one
:class:`AuditEvent` capturing the telemetry, threat score, selected policy, key
event, posture, and a plain-language explanation. Events are kept in memory,
optionally streamed to a JSON-lines file, and can be printed to the console.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional, TextIO

from ..domain.models import (
    AuditEvent,
    CryptoPolicyDecision,
    KeyRotationEvent,
    PostureState,
    TelemetrySnapshot,
    ThreatScore,
    utc_now,
)


class AuditLogger:
    """Record and expose structured audit events.

    Parameters
    ----------
    jsonl_path:
        Optional path to a JSON-lines file. When set, each event is appended
        as one JSON object per line for downstream SIEM-style ingestion.
    echo_console:
        When True, a compact human-readable line is printed per event.
    """

    def __init__(
        self,
        jsonl_path: Optional[str | Path] = None,
        echo_console: bool = False,
    ) -> None:
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self.echo_console = echo_console
        self._events: list[AuditEvent] = []
        self._fh: Optional[TextIO] = None
        if self.jsonl_path is not None:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.jsonl_path.open("a", encoding="utf-8")

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def record(
        self,
        session_id: str,
        tick_number: int,
        telemetry: TelemetrySnapshot,
        threat: ThreatScore,
        policy: CryptoPolicyDecision,
        key_event: KeyRotationEvent,
        posture: PostureState,
        explanation: str,
        council: Optional[dict] = None,
    ) -> AuditEvent:
        """Build, store, and emit a single audit event."""
        event = AuditEvent(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            timestamp=utc_now(),
            session_id=session_id,
            tick_number=tick_number,
            telemetry=telemetry.to_dict(),
            threat_score=threat.to_dict(),
            selected_policy=policy.to_dict(),
            key_rotation_event=key_event.to_dict(),
            posture_state=posture.to_dict(),
            explanation=explanation,
            council=council,
        )
        self._events.append(event)

        if self._fh is not None:
            self._fh.write(json.dumps(event.to_dict()) + "\n")
            self._fh.flush()

        if self.echo_console:
            print(self.format_console(event))

        return event

    @staticmethod
    def format_console(event: AuditEvent) -> str:
        """A compact one-line console representation of an event."""
        return (
            f"[tick {event.tick_number:>3}] "
            f"{event.threat_score['risk_level']:<8} "
            f"score={event.threat_score['numeric_score']:.2f} "
            f"policy={event.selected_policy['policy_name']} "
            f"rotated={event.key_rotation_event['rotated']} "
            f":: {event.explanation}"
        )

    def export(self) -> list[dict]:
        """Return all events as JSON-friendly dicts."""
        return [e.to_dict() for e in self._events]

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
