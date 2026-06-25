"""Tests for the standard-library web preview layer."""

from __future__ import annotations

import json

import pytest

from marvin.domain.enums import Scenario
from marvin.simulation.runner import SimulationRunner
from marvin.web.server import (
    MarvinHandler,
    _scenarios_payload,
    build_session_payload,
)


def test_build_session_payload_shape():
    result = SimulationRunner().run_session(
        scenario=Scenario.SUSPECTED_INTERCEPTION, ticks=5, seed=7
    )
    payload = build_session_payload(result)
    assert payload["scenario"] == "SUSPECTED_INTERCEPTION"
    assert payload["seed"] == 7
    assert payload["ticks"] == 5
    assert len(payload["decisions"]) == 5
    assert len(payload["audit"]) == 5
    # Payload must be JSON-serialisable end to end.
    json.dumps(payload)

    first = payload["decisions"][0]
    for key in (
        "tick",
        "risk_level",
        "risk_score",
        "policy",
        "key_action",
        "next_action",
        "explanation",
    ):
        assert key in first


def test_run_simulation_is_deterministic_via_api():
    a = MarvinHandler._run_simulation(
        {"scenario": "CREDENTIAL_STUFFING", "ticks": 8, "seed": 42}
    )
    b = MarvinHandler._run_simulation(
        {"scenario": "CREDENTIAL_STUFFING", "ticks": 8, "seed": 42}
    )
    a_levels = [d["risk_level"] for d in a["decisions"]]
    b_levels = [d["risk_level"] for d in b["decisions"]]
    assert a_levels == b_levels


def test_run_simulation_clamps_ticks():
    payload = MarvinHandler._run_simulation({"scenario": "LOW_RISK_NORMAL_OPERATION", "ticks": 9999})
    assert payload["ticks"] <= 200


def test_run_simulation_rejects_unknown_scenario():
    with pytest.raises(ValueError):
        MarvinHandler._run_simulation({"scenario": "DOES_NOT_EXIST"})


def test_run_simulation_rejects_bad_seed():
    with pytest.raises(ValueError):
        MarvinHandler._run_simulation(
            {"scenario": "LOW_RISK_NORMAL_OPERATION", "seed": "abc"}
        )


def test_scenarios_payload_covers_all_scenarios():
    payload = _scenarios_payload()
    names = {p["name"] for p in payload}
    assert names == {s.value for s in Scenario}
    assert all(p["description"] for p in payload)
