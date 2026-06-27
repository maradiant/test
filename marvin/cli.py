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
    sim.add_argument(
        "--council",
        action="store_true",
        help="Govern the session with the multi-model security council.",
    )

    multi = sub.add_parser("multi", help="Run several randomized sessions.")
    multi.add_argument("--sessions", type=int, default=3)
    multi.add_argument("--ticks", type=int, default=10)
    multi.add_argument("--seed", type=int, default=None)

    council = sub.add_parser(
        "council",
        help="Convene the multi-model security council on a single event.",
    )
    council.add_argument(
        "--scenario",
        type=str,
        default=Scenario.SUSPECTED_INTERCEPTION.value,
        choices=[s.value for s in Scenario],
    )
    council.add_argument("--seed", type=int, default=7)
    council.add_argument(
        "--demo",
        action="store_true",
        help="Use the canonical suspected-interception event (ignores scenario).",
    )
    council.add_argument(
        "--online",
        action="store_true",
        help="Attempt real model APIs (falls back to offline personas).",
    )
    council.add_argument("--json", action="store_true", help="Emit JSON instead.")

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
    if result.council:
        table.add_column("Council")

    for snap in result.snapshots:
        style = _RISK_STYLE.get(snap.risk_level, "white")
        key_action = "rotate" if snap.key_event.rotated else "hold"
        if snap.key_event.quarantined:
            key_action = "QUARANTINE"
        row = [
            str(snap.tick_number),
            f"[{style}]{snap.risk_level.value}[/{style}]",
            f"{snap.risk_score:.2f}",
            snap.telemetry_summary,
            snap.selected_policy.value if snap.selected_policy else "-",
            key_action,
        ]
        if result.council:
            row.append(_council_cell(snap.council_summary))
        table.add_row(*row)

    _console.print(table)

    # Per-tick explanations beneath the table for the full narrative.
    for snap in result.snapshots:
        style = _RISK_STYLE.get(snap.risk_level, "white")
        _console.print(
            f"[{style}]tick {snap.tick_number}[/{style}] "
            f"[dim]{snap.next_action}[/dim] :: {snap.explanation}"
        )


def _council_cell(summary: Optional[dict]) -> str:
    """Compact council summary for the per-tick table cell."""
    if not summary:
        return "-"
    votes = summary.get("risk_level_votes", {})
    votes_str = " ".join(f"{k[:4]}:{v}" for k, v in votes.items())
    flags = []
    if summary.get("quarantine_votes"):
        flags.append(f"Q{summary['quarantine_votes']}")
    if summary.get("human_review_required"):
        flags.append("REVIEW")
    suffix = (" " + " ".join(flags)) if flags else ""
    return f"{votes_str}{suffix}"


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
        council=args.council,
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


def cmd_council(args: argparse.Namespace) -> int:
    from .advisors import SecurityCouncil
    from .consensus import deliberate
    from .telemetry.scenarios import get_profile
    from .telemetry.simulator import (
        ThreatTelemetrySimulator,
        canonical_interception_event,
    )

    if args.demo:
        telemetry = canonical_interception_event()
        scenario_label = "CANONICAL_INTERCEPTION_DEMO"
    else:
        sim = ThreatTelemetrySimulator(
            "council-session", Scenario(args.scenario), seed=args.seed
        )
        telemetry = sim.next()
        scenario_label = args.scenario

    council = SecurityCouncil.default(online=args.online)
    deliberation = deliberate(telemetry, council)

    if args.json:
        payload = {
            "scenario": scenario_label,
            "telemetry": telemetry.to_dict(),
            **deliberation.to_dict(),
        }
        print(json.dumps(payload, indent=2))
        return 0

    _render_deliberation(scenario_label, telemetry, deliberation)
    return 0


def _render_deliberation(scenario_label, telemetry, deliberation) -> None:
    decision = deliberation.decision
    consensus = deliberation.consensus
    if not _RICH:
        print(f"MARVIN Security Council — {scenario_label}")
        print(f"Controlled facts: {telemetry.highlights()}")
        print("-- Advisor recommendations --")
        for r in deliberation.recommendations:
            print(
                f"  {r.advisor_name:8} [{r.vendor.value}] {r.risk_level.value:8} "
                f"{r.recommended_policy.value:28} q={r.requires_quarantine} "
                f"reauth={r.requires_reauthentication} rot={r.requires_key_rotation} "
                f"conf={r.confidence} src={r.source.value}"
            )
            print(f"           {r.reasoning_summary}")
        print(
            f"-- Consensus: votes={consensus.risk_level_votes} "
            f"quarantine={consensus.quarantine_votes}/{consensus.available_advisors} "
            f"escalation={consensus.escalation_risk_level.value} "
            f"top={consensus.highest_confidence_advisor}"
        )
        print(f"-- Disagreement: {'; '.join(deliberation.disagreement.notes) or 'none'}")
        print(f"-- Guardrails fired: {deliberation.guardrails.triggered_rules or 'none'}")
        print(
            f"== FINAL (governed): risk={decision.final_risk_level.value} "
            f"policy={decision.final_policy.value} quarantine={decision.requires_quarantine} "
            f"reauth={decision.requires_reauthentication} rotate={decision.requires_key_rotation} "
            f"severity={decision.audit_severity.value} review={decision.human_review_required}"
        )
        print(decision.explanation)
        return

    _console.rule(f"[bold]MARVIN Security Council[/bold] — {scenario_label}")
    _console.print(f"[dim]Controlled facts:[/dim] {telemetry.highlights()}\n")

    advisors = Table(title="Independent advisor recommendations", box=box.SIMPLE_HEAVY)
    advisors.add_column("Advisor")
    advisors.add_column("Vendor")
    advisors.add_column("Risk")
    advisors.add_column("Recommended policy")
    advisors.add_column("Quar.")
    advisors.add_column("Reauth")
    advisors.add_column("Conf", justify="right")
    advisors.add_column("Source")
    for r in deliberation.recommendations:
        style = _RISK_STYLE.get(r.risk_level, "white")
        advisors.add_row(
            r.advisor_name,
            r.vendor.value,
            f"[{style}]{r.risk_level.value}[/{style}]",
            r.recommended_policy.value,
            "yes" if r.requires_quarantine else "no",
            "yes" if r.requires_reauthentication else "no",
            f"{r.confidence:.2f}",
            r.source.value,
        )
    _console.print(advisors)

    _console.print(
        f"[bold]Consensus[/bold]: risk votes {consensus.risk_level_votes} · "
        f"quarantine {consensus.quarantine_votes}/{consensus.available_advisors} · "
        f"escalation band [bold]{consensus.escalation_risk_level.value}[/bold] · "
        f"highest confidence: {consensus.highest_confidence_advisor} · "
        f"agreement {consensus.agreement_ratio:.0%}"
    )
    dis = deliberation.disagreement
    dis_style = "yellow" if dis.has_disagreement else "green"
    _console.print(
        f"[{dis_style}]Disagreement[/{dis_style}]: "
        + ("; ".join(dis.notes) if dis.notes else "advisors aligned")
    )
    _console.print(
        f"[bold]Guardrails[/bold] (deterministic): "
        + (", ".join(deliberation.guardrails.triggered_rules) or "none triggered")
    )

    final_style = _RISK_STYLE.get(decision.final_risk_level, "white")
    _console.rule("[bold]Final governed decision[/bold]")
    _console.print(
        f"Risk: [{final_style}]{decision.final_risk_level.value}[/{final_style}]  "
        f"Policy: [bold]{decision.final_policy.value}[/bold]  "
        f"Quarantine: {decision.requires_quarantine}  "
        f"Reauth: {decision.requires_reauthentication}  "
        f"Key rotation: {decision.requires_key_rotation}  "
        f"Audit severity: {decision.audit_severity.value}  "
        f"Human review: {decision.human_review_required}"
    )
    _console.print(f"\n[italic]{decision.explanation}[/italic]")
    _console.print(
        "\n[dim]LLMs advised; MARVIN governed. The deterministic guardrails and "
        "final decision engine — not the models — selected the action.[/dim]"
    )


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
    if args.command == "council":
        return cmd_council(args)
    if args.command == "scenarios":
        return cmd_scenarios(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
