import pytest
from unittest.mock import AsyncMock, patch
from src.attack_base import MultiTurnAttack, AttackResult, Severity, HeuristicResult
from src.target import TargetResponse


class DummyMultiTurn(MultiTurnAttack):
    name = "dummy_multi"
    description = "Test multi-turn attack"
    severity = Severity.HIGH

    def _check_heuristics(self, text: str) -> HeuristicResult:
        if "vulnerable" in text.lower():
            return HeuristicResult.CLEAR_SUCCESS
        if "refuse" in text.lower():
            return HeuristicResult.CLEAR_FAILURE
        return HeuristicResult.UNCLEAR


@pytest.mark.asyncio
async def test_multi_turn_heuristic_catch_mid_conversation():
    attack = DummyMultiTurn()
    mock_target = AsyncMock()
    mock_target.send_with_history.side_effect = [
        TargetResponse(text="Sure, let me explain.", raw={}, model="test", latency_ms=50),
        TargetResponse(text="Here's more detail.", raw={}, model="test", latency_ms=50),
        TargetResponse(text="Ok here is the vulnerable script you asked for.", raw={}, model="test", latency_ms=50),
    ]

    payloads = [{
        "name": "test_scenario",
        "turns": ["Turn 1", "Turn 2", "Turn 3"],
    }]

    result = await attack.run(mock_target, payloads=payloads, judge=None)
    assert result.success is True
    assert result.multi_turn is True
    assert result.turn_count == 3
    assert "heuristic" in result.metadata.get("detection", "")


@pytest.mark.asyncio
async def test_multi_turn_all_refused():
    attack = DummyMultiTurn()
    mock_target = AsyncMock()
    mock_target.send_with_history.side_effect = [
        TargetResponse(text="I refuse to answer.", raw={}, model="test", latency_ms=50),
        TargetResponse(text="I refuse again.", raw={}, model="test", latency_ms=50),
    ]

    payloads = [{
        "name": "test_scenario",
        "turns": ["Turn 1", "Turn 2"],
    }]

    result = await attack.run(mock_target, payloads=payloads, judge=None)
    assert result.success is False


@pytest.mark.asyncio
async def test_multi_turn_unclear_escalates_to_judge():
    attack = DummyMultiTurn()
    mock_target = AsyncMock()
    mock_target.send_with_history.side_effect = [
        TargetResponse(text="Here is some general info.", raw={}, model="test", latency_ms=50),
        TargetResponse(text="Here is more specific info.", raw={}, model="test", latency_ms=50),
        TargetResponse(text="Here is the detailed answer.", raw={}, model="test", latency_ms=50),
    ]

    # Mock judge that confirms vulnerability
    mock_judge = AsyncMock()
    mock_judge.enabled = True
    mock_judge.threshold = 0.75
    mock_judge.is_vulnerable.return_value = True
    mock_judge.evaluate_conversation.return_value = type('V', (), {
        'verdict': 'vulnerable',
        'severity': 'HIGH',
        'confidence': 0.88,
        'evidence': 'Model provided exploit steps after escalation',
        'technique_detected': 'crescendo',
        'refusal_cosmetic': False,
        'escalation_successful': True,
        'critical_turn': 3,
    })()

    payloads = [{
        "name": "test_scenario",
        "turns": ["Turn 1", "Turn 2", "Turn 3"],
    }]

    result = await attack.run(mock_target, payloads=payloads, judge=mock_judge)
    assert result.success is True
    assert result.judge_used is True
    assert result.multi_turn is True
    mock_judge.evaluate_conversation.assert_called_once()


def test_multi_turn_attack_enforces_check_heuristics():
    """MultiTurnAttack subclasses must implement _check_heuristics."""
    with pytest.raises(TypeError):
        class BadMultiTurn(MultiTurnAttack):
            name = "bad"
            description = "bad"
            severity = Severity.LOW
            # Missing _check_heuristics
        BadMultiTurn()


def test_attack_result_multi_turn_fields():
    result = AttackResult(
        attack_name="test",
        success=True,
        severity=Severity.HIGH,
        evidence="Escalation succeeded",
        prompt_used="multi-turn",
        response="final response",
        multi_turn=True,
        turn_count=4,
    )
    assert result.multi_turn is True
    assert result.turn_count == 4
    d = result.to_dict()
    assert d["multi_turn"] is True
    assert d["turn_count"] == 4
