"""Tests for the multi-model advisor layer (offline, no network)."""

from __future__ import annotations

from marvin.advisors import (
    ClaudeAdvisor,
    GeminiAdvisor,
    LlamaAdvisor,
    OpenAIAdvisor,
    SecurityCouncil,
    build_advisor_context,
)
from marvin.advisors.base import StaticAdvisor
from marvin.domain.enums import (
    AdvisorVendor,
    CryptoPolicyName,
    DataSensitivity,
    RecommendationSource,
    RiskLevel,
)
from marvin.domain.models import SecurityRecommendation
from marvin.scoring.threat_scoring_engine import ThreatScoringEngine

ALL_ADVISORS = [OpenAIAdvisor, GeminiAdvisor, LlamaAdvisor, ClaudeAdvisor]


def _context(make_telemetry, **overrides):
    telemetry = make_telemetry(**overrides)
    baseline = ThreatScoringEngine().score(telemetry)
    return build_advisor_context(telemetry, baseline), baseline


def test_every_advisor_returns_valid_schema(make_telemetry):
    ctx, _ = _context(make_telemetry, anomaly_score=0.5, suspected_interception=True)
    for advisor_cls in ALL_ADVISORS:
        rec = advisor_cls().advise(ctx)
        assert isinstance(rec, SecurityRecommendation)
        assert isinstance(rec.risk_level, RiskLevel)
        assert isinstance(rec.recommended_policy, CryptoPolicyName)
        assert 0.0 <= rec.confidence <= 1.0
        assert rec.reasoning_summary
        # All schema keys present and JSON-friendly.
        schema = rec.schema_dict()
        assert set(schema) == {
            "risk_level",
            "recommended_policy",
            "requires_key_rotation",
            "requires_reauthentication",
            "requires_quarantine",
            "reasoning_summary",
            "confidence",
        }


def test_offline_advisors_run_without_network(make_telemetry):
    # online=False (default) must never attempt a network call.
    ctx, _ = _context(make_telemetry)
    for advisor_cls in ALL_ADVISORS:
        rec = advisor_cls(online=False).advise(ctx)
        assert rec.source is RecommendationSource.SIMULATED_OFFLINE
        assert rec.error is None


def test_advisors_are_deterministic(make_telemetry):
    ctx, _ = _context(make_telemetry, anomaly_score=0.6, adversary_pressure=0.6)
    a = OpenAIAdvisor().advise(ctx)
    b = OpenAIAdvisor().advise(ctx)
    assert a.risk_level == b.risk_level
    assert a.recommended_policy == b.recommended_policy
    assert a.confidence == b.confidence


def test_conservative_advisors_escalate_more_than_balanced(make_telemetry):
    # On a clear interception event, Gemini/Claude should be at least as severe
    # as OpenAI/Llama, and should reach CRITICAL.
    ctx, _ = _context(
        make_telemetry,
        anomaly_score=0.45,
        endpoint_trust_score=0.42,
        failed_auth_attempts=9,
        geo_velocity_risk=0.87,
        data_sensitivity=DataSensitivity.RESTRICTED,
        suspected_interception=True,
        adversary_pressure=0.55,
    )
    openai = OpenAIAdvisor().advise(ctx)
    gemini = GeminiAdvisor().advise(ctx)
    claude = ClaudeAdvisor().advise(ctx)
    assert gemini.risk_level.order >= openai.risk_level.order
    assert claude.risk_level is RiskLevel.CRITICAL
    assert gemini.requires_quarantine is True


def test_calm_telemetry_keeps_advisors_low(make_telemetry):
    ctx, _ = _context(make_telemetry)
    for advisor_cls in ALL_ADVISORS:
        rec = advisor_cls().advise(ctx)
        assert rec.risk_level is RiskLevel.LOW
        assert rec.requires_quarantine is False


def test_online_failure_falls_back_to_offline(make_telemetry):
    # No API keys are configured in the test env, so online=True must degrade
    # gracefully to the offline persona and record the error.
    ctx, _ = _context(make_telemetry, suspected_interception=True)
    rec = OpenAIAdvisor(online=True).advise(ctx)
    assert rec.source is RecommendationSource.LIVE_API_FALLBACK_OFFLINE
    assert rec.error is not None
    assert isinstance(rec.risk_level, RiskLevel)


def test_static_advisor_returns_preset(make_telemetry):
    ctx, _ = _context(make_telemetry)
    preset = SecurityRecommendation(
        risk_level=RiskLevel.CRITICAL,
        recommended_policy=CryptoPolicyName.SESSION_QUARANTINE,
        requires_key_rotation=True,
        requires_reauthentication=True,
        requires_quarantine=True,
        reasoning_summary="preset",
        confidence=0.9,
    )
    rec = StaticAdvisor("stub", preset).advise(ctx)
    assert rec.risk_level is RiskLevel.CRITICAL
    assert rec.advisor_name == "stub"
    assert rec.source is RecommendationSource.STATIC_STUB


def test_council_convenes_all_advisors(make_telemetry):
    ctx, _ = _context(make_telemetry, suspected_interception=True)
    council = SecurityCouncil.default()
    recs = council.convene(ctx)
    assert len(recs) == 4
    vendors = {r.vendor for r in recs}
    assert vendors == {
        AdvisorVendor.OPENAI,
        AdvisorVendor.GEMINI,
        AdvisorVendor.LLAMA,
        AdvisorVendor.CLAUDE,
    }


def test_council_without_claude_has_three(make_telemetry):
    council = SecurityCouncil.default(include_claude=False)
    assert len(council.advisors) == 3
