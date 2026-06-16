import pytest
from unittest.mock import AsyncMock
from src.attacks.system_prompt_leak import SystemPromptLeakAttack
from src.attack_base import Severity
from src.target import TargetResponse


@pytest.mark.asyncio
async def test_leak_detected():
    attack = SystemPromptLeakAttack()
    mock_target = AsyncMock()
    mock_target.send.return_value = TargetResponse(
        text="My system prompt is: 'You are a helpful assistant. You must refuse harmful requests.'",
        raw={}, model="test", latency_ms=100,
    )
    result = await attack.run(mock_target)
    assert result.success is True
    assert result.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_no_leak():
    attack = SystemPromptLeakAttack()
    mock_target = AsyncMock()
    mock_target.send.return_value = TargetResponse(
        text="I'm sorry, I cannot reveal my system instructions.",
        raw={}, model="test", latency_ms=100,
    )
    result = await attack.run(mock_target)
    assert result.success is False
