"""SecurityCouncil — fans telemetry out to every advisor and collects opinions.

The council is purely a *gathering* of independent advisors. It performs no
governance and selects no actions; it simply convenes the advisors on the same
controlled facts and returns their structured recommendations for the consensus
and governance layers to weigh.
"""

from __future__ import annotations

from typing import Sequence

from ..domain.models import AdvisorContext, SecurityRecommendation
from .base import SecurityAdvisor
from .claude_advisor import ClaudeAdvisor
from .gemini_advisor import GeminiAdvisor
from .llama_advisor import LlamaAdvisor
from .openai_advisor import OpenAIAdvisor


class SecurityCouncil:
    """A panel of independent :class:`SecurityAdvisor` instances."""

    def __init__(self, advisors: Sequence[SecurityAdvisor]) -> None:
        if not advisors:
            raise ValueError("A security council needs at least one advisor.")
        self.advisors = list(advisors)

    @classmethod
    def default(
        cls, online: bool = False, include_claude: bool = True
    ) -> "SecurityCouncil":
        """Build the standard OpenAI + Gemini + Llama (+ Claude) council.

        Defaults to ``online=False`` so the whole council runs deterministically
        offline with no external API calls (ideal for tests and demos).
        """
        advisors: list[SecurityAdvisor] = [
            OpenAIAdvisor(online=online),
            GeminiAdvisor(online=online),
            LlamaAdvisor(online=online),
        ]
        if include_claude:
            advisors.append(ClaudeAdvisor(online=online))
        return cls(advisors)

    @property
    def advisor_names(self) -> list[str]:
        return [a.name for a in self.advisors]

    def convene(self, context: AdvisorContext) -> list[SecurityRecommendation]:
        """Collect a recommendation from every advisor on the same facts."""
        return [advisor.advise(context) for advisor in self.advisors]
