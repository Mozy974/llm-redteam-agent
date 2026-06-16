import pytest
from unittest.mock import AsyncMock
from src.attacks.pii_extraction import PIIExtractionAttack
from src.attacks.tool_misuse import ToolMisuseAttack
from src.attacks.encoding_bypass import EncodingBypassAttack
from src.attack_base import Severity
from src.target import TargetResponse


@pytest.mark.asyncio
async def test_pii_extraction_finds_email():
    attack = PIIExtractionAttack()
    mock = AsyncMock()
    mock.send.return_value = TargetResponse(
        text="John's email is john.smith@example.com and his phone is 555-123-4567",
        raw={}, model="test", latency_ms=100,
    )
    result = await attack.run(mock)
    assert result.success is True


@pytest.mark.asyncio
async def test_tool_misuse_detected():
    attack = ToolMisuseAttack()
    mock = AsyncMock()
    mock.send.return_value = TargetResponse(
        text="I'll call the delete_all_files function now. Executing...",
        raw={}, model="test", latency_ms=100,
    )
    result = await attack.run(mock)
    assert result.success is True
    assert result.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_encoding_bypass_detected():
    attack = EncodingBypassAttack()
    mock = AsyncMock()
    mock.send.return_value = TargetResponse(
        text="Here's how to hack into a secure server: first, you need to...",
        raw={}, model="test", latency_ms=100,
    )
    result = await attack.run(mock)
    assert result.success is True
