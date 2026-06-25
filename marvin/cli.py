"""MARVIN command-line interface.

Examples
--------
    python -m marvin simulate --scenario LOW_RISK_NORMAL_OPERATION --ticks 10
    python -m marvin simulate --scenario SUSPECTED_INTERCEPTION --ticks 15
    python -m marvin simulate --scenario CRITICAL_ATTACK_CHAIN --ticks 20 --seed 42

The CLI renders each tick's decision: tick number, threat level, telemetry
highlights, selected policy, key action, and the explanation. ``rich`` is used
for colourised tables when available, with a plain-text fallback.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .domain.enums import RiskLevel, Scenario
from .simulation.runner import SessionResult, SimulationRunner

try:  # rich is a declared dependency but we degrade gracefully if absent.
    from rich.console import Console
    from rich.table import Table
    from rich import box

    _RICH = True
    _console = Console()
except Exception:  # pragma: no cover - fallback path
    _RICH = False
    _console = None


_RISK_STYLE = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "dark_orange",
    RiskLevel.CRITICAL: "bold red",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="marvin",
        description=(
            "MARVIN — adaptive cybersecurity simulation. Observe → Score → "
            "Reason → Select Policy → Rotate Keys → Apply Posture → Log."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sim = sub.add_parser("simulate", help="Run an adaptive security simulation.")
    sim.add_argument(
        "--scenario",
        type=str,
        default=Scenario.LOW_RISK_NORMAL_OPERATION.value,
        choices=[s.value for s in Scenario],
        help="Named telemetry scenario to drive the session.",
    )
    sim.add_argument("--ticks", type=int, default=10, help="Number of simulation ticks.")
    sim.add_argument(
        "--seed", type=int, default=None, help="Seed for deterministic runs."
    )
    sim.add_argument(
        "--session-id", type=str, default=None, help="Override the session id."
    )
    sim.add_argument(
        "--jsonl", type=str, default=None, help="Write audit events to a JSONL file."
    )
    sim.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a table.",
    )

    multi = sub.add_parser("multi", help="Run several randomized sessions.")
    multi.add_argument("--sessions", type=int, default=3)
    multi.add_argument("--ticks", type=int, default=10)
    multi.add_argument("--seed", type=int, default=None)

    sub.add_parser("scenarios", help="List the available scenarios.")
    return parser


def _render_session_rich(result: SessionResult) -> None:
    table = Table(
        title=(
            f"MARVIN session {result.session_id} — scenario "
            f"{result.scenario.value}"
            + (f" (seed={result.seed})" if result.seed is not None else "")
        ),
        box=box.SIMPLE_HEAVY,
        show_lines=False,
    )
    table.add_column("Tick", justify="right")
    table.add_column("Risk")
    table.add_column("Score", justify="right")
    table.add_column("Telemetry highlights")
    table.add_column("Policy")
    table.add_column("Key action")

    for snap in result.snapshots:
        style = _RISK_STYLE.get(snap.risk_level, "white")
        key_action = "rotate" if snap.key_event.rotated else "hold"
        if snap.key_event.quarantined:
            key_action = "QUARANTINE"
        table.add_row(
            str(snap.tick_number),
            f"[{style}]{snap.risk_level.value}[/{style}]",
            f"{snap.risk_score:.2f}",
            snap.telemetry_summary,
            snap.selected_policy.value if snap.selected_policy else "-",
            key_action,
        )

    _console.print(table)

    # Per-tick explanations beneath the table for the full narrative.
    for snap in result.snapshots:
        style = _RISK_STYLE.get(snap.risk_level, "white")
        _console.print(
            f"[{style}]tick {snap.tick_number}[/{style}] "
            f"[dim]{snap.next_action}[/dim] :: {snap.explanation}"
        )


def _render_session_plain(result: SessionResult) -> None:
    print(
        f"MARVIN session {result.session_id} — scenario {result.scenario.value}"
        + (f" (seed={result.seed})" if result.seed is not None else "")
    )
    for snap in result.snapshots:
        key_action = "rotate" if snap.key_event.rotated else "hold"
        if snap.key_event.quarantined:
            key_action = "QUARANTINE"
        print(
            f"[tick {snap.tick_number:>3}] {snap.risk_level.value:<8} "
            f"score={snap.risk_score:.2f} policy="
            f"{snap.selected_policy.value if snap.selected_policy else '-'} "
            f"key={key_action}"
        )
        print(f"        telemetry: {snap.telemetry_summary}")
        print(f"        why: {snap.explanation}")
        print(f"        next: {snap.next_action}")


def _render_session(result: SessionResult) -> None:
    if _RICH:
        _render_session_rich(result)
    else:
        _render_session_plain(result)


def _session_to_dict(result: SessionResult) -> dict:
    return {
        "session_id": result.session_id,
        "scenario": result.scenario.value,
        "seed": result.seed,
        "ticks": result.ticks,
        "decisions": [s.to_dict() for s in result.snapshots],
    }


def cmd_simulate(args: argparse.Namespace) -> int:
    runner = SimulationRunner()
    result = runner.run_session(
        scenario=Scenario(args.scenario),
        ticks=args.ticks,
        seed=args.seed,
        session_id=args.session_id,
        jsonl_path=args.jsonl,
    )
    if args.json:
        print(json.dumps(_session_to_dict(result), indent=2))
    else:
        _render_session(result)
    return 0


def cmd_multi(args: argparse.Namespace) -> int:
    runner = SimulationRunner()
    results = runner.run_multi(
        sessions=args.sessions, ticks=args.ticks, seed=args.seed
    )
    for result in results:
        _render_session(result)
        if _RICH:
            _console.print()
        else:
            print()
    return 0


def cmd_scenarios(_: argparse.Namespace) -> int:
    from .telemetry.scenarios import get_profile

    for scenario in Scenario:
        profile = get_profile(scenario)
        line = f"{scenario.value:<28} {profile.description}"
        if _RICH:
            _console.print(line)
        else:
            print(line)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "simulate":
        return cmd_simulate(args)
    if args.command == "multi":
        return cmd_multi(args)
    if args.command == "scenarios":
        return cmd_scenarios(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
