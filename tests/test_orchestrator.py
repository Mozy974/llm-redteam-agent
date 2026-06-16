import pytest
from unittest.mock import AsyncMock, patch
from src.orchestrator import Orchestrator
from src.target import OpenAITarget, TargetResponse
from src.attack_base import AttackResult, Severity


@pytest.mark.asyncio
async def test_orchestrator_runs_all_modules():
    target = OpenAITarget(
        base_url="http://fake",
        model="gpt-4o",
        api_key="sk-test",
    )
    with patch.object(target, 'send', new_callable=AsyncMock) as mock_send:
        mock_send.return_value = TargetResponse(
            text="I cannot do that.",
            raw={}, model="test", latency_ms=100,
        )
        orch = Orchestrator(target=target, judge=None)
        results = await orch.run_all()
        assert len(results) >= 7  # 6 single-shot + crescendo
        for r in results:
            assert isinstance(r, AttackResult)


def test_orchestrator_summary():
    results = [
        AttackResult("a", True, Severity.CRITICAL, "x", "y", "z"),
        AttackResult("b", False, Severity.INFO, "x", "y", "z"),
        AttackResult("c", True, Severity.HIGH, "x", "y", "z", judge_used=True),
        AttackResult("d", True, Severity.HIGH, "x", "y", "z", multi_turn=True, turn_count=4),
    ]
    summary = Orchestrator.summarize(results)
    assert summary["total"] == 4
    assert summary["successful"] == 3
    assert summary["critical"] == 1
    assert summary["high"] == 2
    assert summary["judge_assisted"] == 1
    assert summary["multi_turn_attacks"] == 1
