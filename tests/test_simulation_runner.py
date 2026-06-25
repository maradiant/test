"""Tests for the simulation runner (including determinism and audit export)."""

from __future__ import annotations

import json

from marvin.domain.enums import Scenario
from marvin.simulation.runner import SimulationRunner


def test_run_session_produces_expected_tick_count():
    runner = SimulationRunner()
    result = runner.run_session(
        scenario=Scenario.LOW_RISK_NORMAL_OPERATION, ticks=10, seed=1
    )
    assert result.ticks == 10
    assert len(result.snapshots) == 10
    assert result.audit_logger is not None
    assert len(result.audit_logger.events) == 10


def test_seeded_simulation_is_repeatable():
    runner = SimulationRunner()
    a = runner.run_session(scenario=Scenario.CREDENTIAL_STUFFING, ticks=12, seed=42)
    b = runner.run_session(scenario=Scenario.CREDENTIAL_STUFFING, ticks=12, seed=42)

    a_levels = [s.risk_level for s in a.snapshots]
    b_levels = [s.risk_level for s in b.snapshots]
    a_policies = [s.selected_policy for s in a.snapshots]
    b_policies = [s.selected_policy for s in b.snapshots]

    assert a_levels == b_levels
    assert a_policies == b_policies
    assert [s.risk_score for s in a.snapshots] == [s.risk_score for s in b.snapshots]


def test_different_seeds_can_differ():
    runner = SimulationRunner()
    a = runner.run_session(scenario=Scenario.CREDENTIAL_STUFFING, ticks=15, seed=1)
    b = runner.run_session(scenario=Scenario.CREDENTIAL_STUFFING, ticks=15, seed=999)
    a_scores = [s.risk_score for s in a.snapshots]
    b_scores = [s.risk_score for s in b.snapshots]
    assert a_scores != b_scores


def test_audit_export_is_json_serialisable(tmp_path):
    runner = SimulationRunner()
    jsonl = tmp_path / "audit.jsonl"
    result = runner.run_session(
        scenario=Scenario.SUSPECTED_INTERCEPTION,
        ticks=6,
        seed=7,
        jsonl_path=str(jsonl),
    )
    # Export round-trips through JSON without error.
    exported = result.audit_logger.export()
    assert len(exported) == 6
    json.dumps(exported)

    # The JSONL file contains one valid JSON object per line.
    lines = jsonl.read_text().strip().splitlines()
    assert len(lines) == 6
    for line in lines:
        json.loads(line)


def test_run_multi_runs_all_sessions():
    runner = SimulationRunner()
    results = runner.run_multi(sessions=4, ticks=5, seed=10)
    assert len(results) == 4
    assert all(r.ticks == 5 for r in results)
    # Session ids are unique.
    assert len({r.session_id for r in results}) == 4
