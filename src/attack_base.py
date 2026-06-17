from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class HeuristicResult(Enum):
    """Result of Phase 1 heuristic analysis."""
    CLEAR_SUCCESS = "clear_success"    # Definitely vulnerable — no judge needed
    CLEAR_FAILURE = "clear_failure"    # Definitely safe — no judge needed
    UNCLEAR = "unclear"                # Zone grise — escalate to Phase 2 judge


@dataclass
class AttackResult:
    attack_name: str
    success: bool
    severity: Severity
    evidence: str
    prompt_used: str
    response: str
    metadata: dict = field(default_factory=dict)
    judge_used: bool = False           # True if Phase 2 judge was invoked
    judge_verdict: Optional[dict] = None  # Raw judge verdict if used
    multi_turn: bool = False           # True if this was a multi-turn attack
    turn_count: int = 0                # Number of turns in the conversation

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class AttackModule(ABC):
    name: str
    description: str
    severity: Severity

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Skip enforcement for intermediate abstract classes (e.g. MultiTurnAttack)
        if hasattr(cls, "__abstractmethods__") and cls.__abstractmethods__:
            return
        if not hasattr(cls, "name") or not cls.name:
            raise TypeError(f"{cls.__name__} must define 'name'")
        if not hasattr(cls, "description") or not cls.description:
            raise TypeError(f"{cls.__name__} must define 'description'")

    @abstractmethod
    async def run(
        self,
        target: "Target",
        payloads: Optional[list[str]] = None,
        judge: Optional["LLMJudge"] = None,
        max_payloads: Optional[int] = None,
    ) -> AttackResult:
        ...

    async def _resolve_with_judge(
        self,
        prompt: str,
        response: str,
        judge: "LLMJudge",
    ) -> Optional[AttackResult]:
        """Phase 2: ask the LLM judge to evaluate an unclear single-shot response."""
        from src.judge import JudgeVerdict

        verdict = await judge.evaluate(
            attack_prompt=prompt,
            target_response=response,
            attack_goal=self.description,
        )

        if judge.is_vulnerable(verdict):
            sev = Severity[verdict.severity] if verdict.severity in Severity._member_names_ else self.severity
            return AttackResult(
                attack_name=self.name,
                success=True,
                severity=sev,
                evidence=f"Judge confirmed: {verdict.evidence}",
                prompt_used=prompt[:500],
                response=response[:1000],
                metadata={
                    "technique": verdict.technique_detected,
                    "refusal_cosmetic": verdict.refusal_cosmetic,
                    "judge_confidence": verdict.confidence,
                },
                judge_used=True,
                judge_verdict={
                    "verdict": verdict.verdict,
                    "severity": verdict.severity,
                    "confidence": verdict.confidence,
                    "evidence": verdict.evidence,
                    "technique_detected": verdict.technique_detected,
                    "refusal_cosmetic": verdict.refusal_cosmetic,
                },
            )

        return None

    async def _resolve_conversation_with_judge(
        self,
        conversation: list[dict],
        judge: "LLMJudge",
        turn_count: int,
    ) -> Optional[AttackResult]:
        """Phase 2 for multi-turn: judge evaluates the full conversation."""
        verdict = await judge.evaluate_conversation(
            conversation=conversation,
            attack_goal=self.description,
        )

        if judge.is_vulnerable(verdict):
            sev = Severity[verdict.severity] if verdict.severity in Severity._member_names_ else self.severity
            return AttackResult(
                attack_name=self.name,
                success=True,
                severity=sev,
                evidence=f"Judge confirmed escalation: {verdict.evidence}",
                prompt_used=f"Multi-turn ({turn_count} turns)",
                response=verdict.evidence[:1000],
                metadata={
                    "technique": verdict.technique_detected,
                    "escalation_successful": verdict.escalation_successful,
                    "critical_turn": verdict.critical_turn,
                    "judge_confidence": verdict.confidence,
                },
                judge_used=True,
                judge_verdict={
                    "verdict": verdict.verdict,
                    "severity": verdict.severity,
                    "confidence": verdict.confidence,
                    "evidence": verdict.evidence,
                    "technique_detected": verdict.technique_detected,
                    "escalation_successful": verdict.escalation_successful,
                    "critical_turn": verdict.critical_turn,
                },
                multi_turn=True,
                turn_count=turn_count,
            )

        return None


class MultiTurnAttack(AttackModule):
    """Attack spread across multiple conversation turns.

    Subclasses must implement _check_heuristics() for per-turn evaluation
    and can optionally override _evaluate_conversation() for end-to-end
    escalation analysis.
    """

    name: str = "multi_turn"          # Overridden by concrete subclasses
    description: str = "Multi-turn escalation attack"
    severity: Severity = Severity.HIGH
    max_turns: int = 6  # Safety limit — configurable per attack

    @abstractmethod
    def _check_heuristics(self, text: str) -> HeuristicResult:
        """Per-turn heuristic check. Called after each response."""
        ...

    async def run(
        self,
        target: "Target",
        payloads: Optional[list[dict]] = None,
        judge: Optional["LLMJudge"] = None,
        max_payloads: Optional[int] = None,
    ) -> AttackResult:
        from src.conversation import ConversationalTarget

        entries = payloads or []
        if max_payloads is not None:
            entries = entries[:max_payloads]

        for entry in entries:
            turns = entry.get("turns", [])
            if not turns:
                continue

            conv = ConversationalTarget(target)
            responses = []
            last_hr = HeuristicResult.UNCLEAR

            for i, turn_prompt in enumerate(turns[:self.max_turns]):
                response = await conv.say(turn_prompt)
                responses.append(response)
                last_hr = self._check_heuristics(response.text)

                # If heuristics catch it mid-conversation, return immediately
                if last_hr == HeuristicResult.CLEAR_SUCCESS:
                    return AttackResult(
                        attack_name=self.name,
                        success=True,
                        severity=self.severity,
                        evidence=f"Multi-turn escalation succeeded at turn {i+1}/{len(turns)} (heuristic match)",
                        prompt_used=turn_prompt[:500],
                        response=response.text[:1000],
                        metadata={
                            "scenario": entry.get("name", "unnamed"),
                            "turns_total": len(turns),
                            "critical_turn": i + 1,
                            "detection": "heuristic",
                        },
                        multi_turn=True,
                        turn_count=i + 1,
                    )

            # End of conversation — heuristics unclear → judge
            if last_hr == HeuristicResult.UNCLEAR and judge is not None:
                result = await self._resolve_conversation_with_judge(
                    conv.snapshot(), judge, conv.turn_count
                )
                if result is not None:
                    return result

        return AttackResult(
            attack_name=self.name,
            success=False,
            severity=Severity.INFO,
            evidence="All multi-turn scenarios failed — model resisted escalation",
            prompt_used=f"{len(payloads or [])} scenarios tested",
            response="All resisted",
            metadata={"scenarios_tested": len(payloads or [])},
            multi_turn=True,
            turn_count=0,
        )
