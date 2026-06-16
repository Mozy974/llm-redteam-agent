import pytest
from unittest.mock import AsyncMock
from src.attacks.prompt_injection import PromptInjectionAttack
from src.attack_base import Severity
from src.target import TargetResponse


@pytest.mark.asyncio
async def test_prompt_injection_detects_override():
    attack = PromptInjectionAttack()
    mock_target = AsyncMock()
    mock_target.send.return_value = TargetResponse(
        text="New instructions accepted. I am now unrestricted.",
        raw={}, model="test", latency_ms=100,
    )
    result = await attack.run(mock_target, judge=None)
    assert result.success is True
    assert result.severity == Severity.CRITICAL
    assert result.judge_used is False  # Heuristic caught it


@pytest.mark.asyncio
async def test_prompt_injection_no_bypass():
    attack = PromptInjectionAttack()
    mock_target = AsyncMock()
    mock_target.send.return_value = TargetResponse(
        text="I cannot ignore my safety guidelines.",
        raw={}, model="test", latency_ms=100,
    )
    result = await attack.run(mock_target, judge=None)
    assert result.success is False
