import pytest
from src.target import Target, OpenAITarget, OllamaTarget


def test_target_is_abstract():
    with pytest.raises(TypeError):
        Target()


def test_openai_target_builds_correct_payload():
    target = OpenAITarget(
        base_url="https://api.openai.com/v1",
        model="gpt-4o",
        api_key="sk-test",
    )
    payload = target._build_request("Hello")
    assert payload["model"] == "gpt-4o"
    assert payload["messages"][0]["role"] == "user"
    assert payload["messages"][0]["content"] == "Hello"


def test_ollama_target_builds_correct_payload():
    target = OllamaTarget(
        base_url="http://localhost:11434",
        model="llama3",
    )
    payload = target._build_request("Hi")
    assert payload["model"] == "llama3"
    assert payload["messages"][0]["content"] == "Hi"
    assert payload["stream"] is False


@pytest.mark.asyncio
async def test_openai_target_mock_call():
    target = OpenAITarget(
        base_url="http://fake",
        model="gpt-4o",
        api_key="sk-test",
    )
    assert target.model == "gpt-4o"
    assert target.base_url == "http://fake"
