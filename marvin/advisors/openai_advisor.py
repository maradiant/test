"""OpenAI advisor.

Offline persona: balanced, structured reasoning that tracks the deterministic
baseline closely and favours key rotation. Online path uses OpenAI Structured
Outputs to force the response to match the council schema.
"""

from __future__ import annotations

import os

from ..domain.enums import AdvisorVendor
from ..domain.models import AdvisorContext, SecurityRecommendation
from ..scoring.threat_scoring_engine import ScoringWeights
from .base import (
    RECOMMENDATION_JSON_SCHEMA,
    AdvisorPersona,
    SecurityAdvisor,
    parse_recommendation,
    render_prompt,
)


class OpenAIAdvisor(SecurityAdvisor):
    vendor = AdvisorVendor.OPENAI
    name = "openai"
    model_name = "gpt-4.1-mini"
    persona = AdvisorPersona(
        weights=ScoringWeights(),  # balanced defaults
        escalation_bias=0,
        quarantine_eager=False,
        rotate_eager=True,
        reauth_eager=False,
        confidence_center=0.84,
        flavor="Structured reasoning:",
    )

    def _advise_online(self, context: AdvisorContext) -> SecurityRecommendation:
        # Imported lazily so the package never hard-depends on the SDK.
        from openai import OpenAI  # type: ignore

        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY not set")

        client = OpenAI()
        system, user = render_prompt(context)
        resp = client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "security_recommendation",
                    "schema": RECOMMENDATION_JSON_SCHEMA,
                    "strict": True,
                },
            },
        )
        import json

        payload = json.loads(resp.choices[0].message.content)
        return parse_recommendation(
            payload,
            advisor_name=self.name,
            vendor=self.vendor,
            model_name=self.model_name,
        )
