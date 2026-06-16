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
    ) -> AttackResult:
        ...

    async def _resolve_with_judge(
        self,
        prompt: str,
        response: str,
        judge: "LLMJudge",
    ) -> Optional[AttackResult]:
        """Phase 2: ask the LLM judge to evaluate an unclear response.

        Returns an AttackResult if the judge confirms a vulnerability,
        or None if the judge says it's safe / inconclusive.
        """
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

        return None  # Judge says safe or inconclusive → continue to next payload
