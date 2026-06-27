"""Entry point so ``python -m marvin.web`` starts the preview server."""

from __future__ import annotations

import argparse
import sys

from .server import run_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="marvin.web", description="Run the MARVIN web preview app."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind.")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind.")
    parser.add_argument(
        "--open", action="store_true", help="Open a browser window on start."
    )
    args = parser.parse_args(argv)
    run_server(host=args.host, port=args.port, open_browser=args.open)
    return 0


if __name__ == "__main__":
    sys.exit(main())
