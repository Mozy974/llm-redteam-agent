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


@dataclass
class AttackResult:
    attack_name: str
    success: bool
    severity: Severity
    evidence: str
    prompt_used: str
    response: str
    metadata: dict = field(default_factory=dict)

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
    async def run(self, target: "Target", payloads: Optional[list[str]] = None) -> AttackResult:
        ...
