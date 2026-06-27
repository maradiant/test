"""Gemini advisor.

Offline persona: conservative/agentic. Weighs geo-velocity and interception
heavily and escalates the risk band by one when a real threat is present, making
it quick to recommend quarantine. Online path uses the Google GenAI SDK with a
JSON response schema.
"""

from __future__ import annotations

import os

from ..domain.enums import AdvisorVendor
from ..domain.models import AdvisorContext, SecurityRecommendation
from ..scoring.threat_scoring_engine import ScoringWeights
from .base import (
    AdvisorPersona,
    SecurityAdvisor,
    parse_recommendation,
    render_prompt,
)


class GeminiAdvisor(SecurityAdvisor):
    vendor = AdvisorVendor.GEMINI
    name = "gemini"
    model_name = "gemini-2.0-flash"
    persona = AdvisorPersona(
        weights=ScoringWeights(
            geo_velocity_risk=0.12,
            suspected_interception=0.24,
            adversary_pressure=0.16,
            anomaly_score=0.16,
        ),
        escalation_bias=1,
        quarantine_eager=True,
        rotate_eager=True,
        reauth_eager=False,
        confidence_center=0.80,
        flavor="Agentic threat review:",
    )

    def _advise_online(self, context: AdvisorContext) -> SecurityRecommendation:
        from google import genai  # type: ignore
        from google.genai import types  # type: ignore

        if not os.environ.get("GEMINI_API_KEY"):
            raise RuntimeError("GEMINI_API_KEY not set")

        client = genai.Client()
        system, user = render_prompt(context)
        resp = client.models.generate_content(
            model=self.model_name,
            contents=f"{system}\n\n{user}",
            config=types.GenerateContentConfig(response_mime_type="application/json"),
        )
        import json

        payload = json.loads(resp.text)
        return parse_recommendation(
            payload,
            advisor_name=self.name,
            vendor=self.vendor,
            model_name=self.model_name,
        )
