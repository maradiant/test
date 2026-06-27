"""Self-contained web preview for MARVIN.

A zero-dependency web app (Python standard library only) that exposes the same
simulation the CLI uses over a small JSON API and serves a modern single-page
UI. Run with::

    python -m marvin.web

then open http://127.0.0.1:8000 in a browser.
"""

from .server import build_session_payload, run_server

__all__ = ["run_server", "build_session_payload"]
