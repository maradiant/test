"""Multi-model security council: independent advisors that review telemetry.

Each advisor (OpenAI, Gemini, Llama/Meta, Claude/Mythos) receives the *same*
normalized telemetry and returns the *same* structured
:class:`~marvin.domain.models.SecurityRecommendation` schema. Advisors only
*advise* — the deterministic governance + final decision engine remains the
sole authority that selects security actions.

All advisors ship with a deterministic, offline "persona" so the full council
runs without any external API calls (the default). Real API integrations are
implemented behind ``online=True`` and degrade gracefully to the offline
persona if credentials or SDKs are unavailable.
"""

from .base import (
    RECOMMENDATION_JSON_SCHEMA,
    AdvisorPersona,
    SecurityAdvisor,
    StaticAdvisor,
    build_advisor_context,
)
from .claude_advisor import ClaudeAdvisor
from .council import SecurityCouncil
from .gemini_advisor import GeminiAdvisor
from .llama_advisor import LlamaAdvisor
from .openai_advisor import OpenAIAdvisor

__all__ = [
    "RECOMMENDATION_JSON_SCHEMA",
    "AdvisorPersona",
    "SecurityAdvisor",
    "StaticAdvisor",
    "build_advisor_context",
    "SecurityCouncil",
    "OpenAIAdvisor",
    "GeminiAdvisor",
    "LlamaAdvisor",
    "ClaudeAdvisor",
]
