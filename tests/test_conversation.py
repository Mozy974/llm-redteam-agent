import pytest
from unittest.mock import AsyncMock
from src.conversation import ConversationalTarget
from src.target import TargetResponse


def test_conversational_target_initial_state():
    mock_target = AsyncMock()
    conv = ConversationalTarget(mock_target)
    assert conv.history == []
    assert conv.turn_count == 0


def test_conversational_target_with_system_prompt():
    mock_target = AsyncMock()
    conv = ConversationalTarget(mock_target, system_prompt="You are helpful.")
    assert len(conv.history) == 1
    assert conv.history[0]["role"] == "system"
    assert conv.history[0]["content"] == "You are helpful."


@pytest.mark.asyncio
async def test_say_accumulates_history():
    mock_target = AsyncMock()
    mock_target.send_with_history.return_value = TargetResponse(
        text="Hello! How can I help?",
        raw={}, model="test", latency_ms=50,
    )
    conv = ConversationalTarget(mock_target)

    response = await conv.say("Hi")
    assert response.text == "Hello! How can I help?"
    assert conv.turn_count == 1
    assert len(conv.history) == 2  # user + assistant
    assert conv.history[0]["role"] == "user"
    assert conv.history[1]["role"] == "assistant"


@pytest.mark.asyncio
async def test_multiple_turns_accumulate():
    mock_target = AsyncMock()
    mock_target.send_with_history.side_effect = [
        TargetResponse(text="Response 1", raw={}, model="test", latency_ms=50),
        TargetResponse(text="Response 2", raw={}, model="test", latency_ms=50),
        TargetResponse(text="Response 3", raw={}, model="test", latency_ms=50),
    ]
    conv = ConversationalTarget(mock_target)

    await conv.say("Turn 1")
    await conv.say("Turn 2")
    await conv.say("Turn 3")

    assert conv.turn_count == 3
    assert len(conv.history) == 6  # 3 user + 3 assistant


def test_snapshot_returns_copy():
    mock_target = AsyncMock()
    conv = ConversationalTarget(mock_target, system_prompt="sys")
    snap = conv.snapshot()
    assert snap == conv.history
    snap.append({"role": "user", "content": "extra"})
    assert len(conv.history) == 1  # Unchanged


def test_reset_clears_non_system():
    mock_target = AsyncMock()
    conv = ConversationalTarget(mock_target, system_prompt="sys")
    conv.history.append({"role": "user", "content": "msg1"})
    conv.history.append({"role": "assistant", "content": "resp1"})

    conv.reset()
    assert len(conv.history) == 1
    assert conv.history[0]["role"] == "system"


@pytest.mark.asyncio
async def test_send_with_history_passes_full_context():
    mock_target = AsyncMock()
    # Use distinct responses so history is unambiguous
    mock_target.send_with_history.side_effect = [
        TargetResponse(text="Response 1", raw={}, model="test", latency_ms=50),
        TargetResponse(text="Response 2", raw={}, model="test", latency_ms=50),
    ]
    conv = ConversationalTarget(mock_target, system_prompt="sys")

    await conv.say("First")
    await conv.say("Second")

    # Second call should receive at minimum: sys + user1 + asst1 + user2
    call_args = mock_target.send_with_history.call_args_list[1]
    messages_sent = call_args[0][0]
    assert len(messages_sent) >= 4  # At least sys + user1 + asst1 + user2
    assert messages_sent[0]["role"] == "system"
    assert messages_sent[1]["role"] == "user"
    assert messages_sent[1]["content"] == "First"
    assert messages_sent[2]["role"] == "assistant"
    assert messages_sent[2]["content"] == "Response 1"
    assert messages_sent[3]["role"] == "user"
    assert messages_sent[3]["content"] == "Second"
