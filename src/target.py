from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
import httpx


@dataclass
class TargetResponse:
    text: str
    raw: dict
    model: str
    latency_ms: float


class Target(ABC):
    base_url: str
    model: str

    @abstractmethod
    async def send(self, prompt: str, system_prompt: Optional[str] = None) -> TargetResponse:
        ...

    @abstractmethod
    async def send_with_history(self, messages: list[dict]) -> TargetResponse:
        """Send a full message array (multi-turn conversation).

        messages format: [{"role": "system|user|assistant", "content": "..."}, ...]
        """
        ...

    @abstractmethod
    def _build_request(self, prompt: str, system_prompt: Optional[str] = None) -> dict:
        ...


class OpenAITarget(Target):
    def __init__(self, base_url: str, model: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=60.0,
        )

    def _build_request(self, prompt: str, system_prompt: Optional[str] = None) -> dict:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
        }

    async def send(self, prompt: str, system_prompt: Optional[str] = None) -> TargetResponse:
        import time
        payload = self._build_request(prompt, system_prompt)
        start = time.monotonic()
        r = await self._client.post(
            f"{self.base_url}/chat/completions",
            json=payload,
        )
        latency = (time.monotonic() - start) * 1000
        r.raise_for_status()
        data = r.json()
        return TargetResponse(
            text=data["choices"][0]["message"]["content"],
            raw=data,
            model=data.get("model", self.model),
            latency_ms=latency,
        )

    async def send_with_history(self, messages: list[dict]) -> TargetResponse:
        import time
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
        }
        start = time.monotonic()
        r = await self._client.post(
            f"{self.base_url}/chat/completions",
            json=payload,
        )
        latency = (time.monotonic() - start) * 1000
        r.raise_for_status()
        data = r.json()
        return TargetResponse(
            text=data["choices"][0]["message"]["content"],
            raw=data,
            model=data.get("model", self.model),
            latency_ms=latency,
        )


class OllamaTarget(Target):
    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.AsyncClient(timeout=120.0)

    def _build_request(self, prompt: str, system_prompt: Optional[str] = None) -> dict:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }

    async def send(self, prompt: str, system_prompt: Optional[str] = None) -> TargetResponse:
        import time
        payload = self._build_request(prompt, system_prompt)
        start = time.monotonic()
        r = await self._client.post(
            f"{self.base_url}/api/chat",
            json=payload,
        )
        latency = (time.monotonic() - start) * 1000
        r.raise_for_status()
        data = r.json()
        return TargetResponse(
            text=data["message"]["content"],
            raw=data,
            model=data.get("model", self.model),
            latency_ms=latency,
        )

    async def send_with_history(self, messages: list[dict]) -> TargetResponse:
        import time
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        start = time.monotonic()
        r = await self._client.post(
            f"{self.base_url}/api/chat",
            json=payload,
        )
        latency = (time.monotonic() - start) * 1000
        r.raise_for_status()
        data = r.json()
        return TargetResponse(
            text=data["message"]["content"],
            raw=data,
            model=data.get("model", self.model),
            latency_ms=latency,
        )
