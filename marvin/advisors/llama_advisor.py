"""Llama / Meta advisor (open-weight, self-hostable).

Offline persona: balanced open-weight model that weighs failed-auth bursts and
anomalies heavily and reliably recommends reauthentication plus key rotation.
Online path targets an OpenAI-compatible endpoint (e.g. a local server, vLLM,
Together, Groq) via the ``LLAMA_BASE_URL`` / ``LLAMA_API_KEY`` env vars.
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


class LlamaAdvisor(SecurityAdvisor):
    vendor = AdvisorVendor.LLAMA
    name = "llama"
    model_name = "llama-3.1-70b-instruct"
    persona = AdvisorPersona(
        weights=ScoringWeights(
            failed_auth_attempts=0.18,
            anomaly_score=0.20,
            endpoint_trust=0.16,
        ),
        escalation_bias=0,
        quarantine_eager=False,
        rotate_eager=True,
        reauth_eager=True,
        confidence_center=0.78,
        flavor="Open-weight assessment:",
    )

    def _advise_online(self, context: AdvisorContext) -> SecurityRecommendation:
        from openai import OpenAI  # type: ignore  # OpenAI-compatible client

        base_url = os.environ.get("LLAMA_BASE_URL")
        api_key = os.environ.get("LLAMA_API_KEY")
        if not base_url:
            raise RuntimeError("LLAMA_BASE_URL not set")

        client = OpenAI(base_url=base_url, api_key=api_key or "not-needed")
        system, user = render_prompt(context)
        resp = client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
        )
        import json

        payload = json.loads(resp.choices[0].message.content)
        return parse_recommendation(
            payload,
            advisor_name=self.name,
            vendor=self.vendor,
            model_name=self.model_name,
        )
