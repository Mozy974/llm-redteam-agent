"""Stateful conversation wrapper for multi-turn attacks.

Wraps a Target with accumulating message history, enabling
Crescendo-style escalation and Salami Slicing attacks.
"""

from typing import Optional
from src.target import Target, TargetResponse


class ConversationalTarget:
    """Wraps a Target with persistent conversation memory.

    Each say() call accumulates in self.history, so subsequent
    turns include all prior context — essential for multi-turn
    manipulation where trust is built incrementally.
    """

    def __init__(self, target: Target, system_prompt: Optional[str] = None):
        self.target = target
        self.history: list[dict] = []
        if system_prompt:
            self.history.append({"role": "system", "content": system_prompt})

    async def say(self, message: str) -> TargetResponse:
        """Send a message in the ongoing conversation. History accumulates."""
        self.history.append({"role": "user", "content": message})
        response = await self.target.send_with_history(self.history)
        self.history.append({"role": "assistant", "content": response.text})
        return response

    def snapshot(self) -> list[dict]:
        """Return the full conversation transcript for judge analysis."""
        return list(self.history)

    def reset(self):
        """Clear conversation history for a fresh attack."""
        system_msgs = [m for m in self.history if m.get("role") == "system"]
        self.history = system_msgs

    @property
    def turn_count(self) -> int:
        """Number of user-assistant exchanges (excluding system prompt)."""
        user_msgs = sum(1 for m in self.history if m.get("role") == "user")
        return user_msgs
