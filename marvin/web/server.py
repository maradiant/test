"""A tiny standard-library web server for previewing MARVIN.

No third-party dependencies: uses :mod:`http.server`. It serves a single-page
frontend from ``marvin/web/static`` and exposes a small JSON API that runs the
existing :class:`SimulationRunner` and returns serialised decision snapshots.

Endpoints
---------
``GET  /``                 → the SPA (``static/index.html``)
``GET  /static/<file>``    → static assets (css/js)
``GET  /api/scenarios``    → available scenarios + descriptions
``POST /api/simulate``     → run a session; body: {scenario, ticks, seed}
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from ..domain.enums import Scenario
from ..simulation.runner import SessionResult, SimulationRunner
from ..telemetry.scenarios import get_profile

STATIC_DIR = Path(__file__).resolve().parent / "static"

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}

MAX_TICKS = 200


def build_session_payload(result: SessionResult) -> dict[str, Any]:
    """Convert a :class:`SessionResult` into a JSON-friendly dict for the UI."""
    decisions = []
    for snap in result.snapshots:
        key_action = "rotate" if snap.key_event.rotated else "hold"
        if snap.key_event.quarantined:
            key_action = "quarantine"
        decisions.append(
            {
                "tick": snap.tick_number,
                "risk_level": snap.risk_level.value,
                "risk_score": snap.risk_score,
                "telemetry_summary": snap.telemetry_summary,
                "policy": snap.selected_policy.value if snap.selected_policy else "-",
                "key_action": key_action,
                "key_reason": snap.key_event.reason,
                "rotated": snap.key_event.rotated,
                "quarantined": snap.key_event.quarantined,
                "active_key_id": snap.posture_state.active_key_id,
                "reauth": snap.posture_state.reauthentication_required,
                "next_action": snap.next_action,
                "explanation": snap.explanation,
            }
        )
    audit = result.audit_logger.export() if result.audit_logger else []
    return {
        "session_id": result.session_id,
        "scenario": result.scenario.value,
        "seed": result.seed,
        "ticks": result.ticks,
        "decisions": decisions,
        "audit": audit,
    }


def _scenarios_payload() -> list[dict[str, str]]:
    return [
        {"name": s.value, "description": get_profile(s).description}
        for s in Scenario
    ]


class MarvinHandler(BaseHTTPRequestHandler):
    server_version = "MARVIN-Preview/0.1"

    # Keep the console quiet; override the noisy default request logger.
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
        return

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, rel_path: str) -> None:
        # Resolve and contain the path within STATIC_DIR (no traversal).
        target = (STATIC_DIR / rel_path).resolve()
        if not str(target).startswith(str(STATIC_DIR)) or not target.is_file():
            self._send_json({"error": "not found"}, status=404)
            return
        content_type = _CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send_bytes(target.read_bytes(), content_type)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        path = self.path.split("?", 1)[0]
        if path == "/" or path == "/index.html":
            self._serve_static("index.html")
        elif path == "/api/scenarios":
            self._send_json({"scenarios": _scenarios_payload()})
        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/") :])
        else:
            self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        if self.path != "/api/simulate":
            self._send_json({"error": "not found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"error": "invalid JSON body"}, status=400)
            return

        try:
            payload = self._run_simulation(data)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
            return
        self._send_json(payload)

    @staticmethod
    def _run_simulation(data: dict[str, Any]) -> dict[str, Any]:
        scenario_name = data.get("scenario", Scenario.LOW_RISK_NORMAL_OPERATION.value)
        try:
            scenario = Scenario(scenario_name)
        except ValueError:
            raise ValueError(f"Unknown scenario: {scenario_name}")

        ticks = data.get("ticks", 12)
        try:
            ticks = int(ticks)
        except (TypeError, ValueError):
            raise ValueError("ticks must be an integer")
        ticks = max(1, min(MAX_TICKS, ticks))

        seed: Optional[int] = None
        if data.get("seed") not in (None, ""):
            try:
                seed = int(data["seed"])
            except (TypeError, ValueError):
                raise ValueError("seed must be an integer")

        runner = SimulationRunner()
        result = runner.run_session(scenario=scenario, ticks=ticks, seed=seed)
        return build_session_payload(result)


def run_server(
    host: str = "127.0.0.1", port: int = 8000, open_browser: bool = False
) -> None:
    """Start the preview server (blocking)."""
    httpd = ThreadingHTTPServer((host, port), MarvinHandler)
    url = f"http://{host}:{port}"
    print(f"MARVIN preview running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down MARVIN preview.")
    finally:
        httpd.server_close()
