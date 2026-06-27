"""Claude / Mythos advisor (optional, security-specialized).

NOTE ON AVAILABILITY: "Mythos" has been described as a cybersecurity-specialized
Anthropic model, but access appears restricted and sourcing is unconfirmed. This
advisor therefore treats Claude/Mythos as *optional*: it runs as a deterministic
offline persona by default and only attempts a live Anthropic API call when
``online=True`` and ``ANTHROPIC_API_KEY`` is configured.

Offline persona: security-specialized and conservative. Weighs interception and
endpoint-trust collapse heavily and escalates the risk band, making it quick to
recommend quarantine and reauthentication.
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


class ClaudeAdvisor(SecurityAdvisor):
    vendor = AdvisorVendor.CLAUDE
    name = "claude"
    # Model id is illustrative; "mythos" availability is unconfirmed.
    model_name = "claude-sonnet (mythos-optional)"
    persona = AdvisorPersona(
        weights=ScoringWeights(
            suspected_interception=0.26,
            endpoint_trust=0.20,
            adversary_pressure=0.16,
        ),
        escalation_bias=1,
        quarantine_eager=True,
        rotate_eager=True,
        reauth_eager=True,
        confidence_center=0.82,
        flavor="Security-specialized review:",
    )

    def _advise_online(self, context: AdvisorContext) -> SecurityRecommendation:
        import anthropic  # type: ignore

        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        client = anthropic.Anthropic()
        system, user = render_prompt(context)
        msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        import json

        text = "".join(block.text for block in msg.content if hasattr(block, "text"))
        payload = json.loads(text)
        return parse_recommendation(
            payload,
            advisor_name=self.name,
            vendor=self.vendor,
            model_name=self.model_name,
        )
