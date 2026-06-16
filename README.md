# ⚡ LLM Red Team Agent

**Autonomous LLM red teaming framework** — test any LLM API against prompt injection, jailbreaking, system prompt leakage, PII extraction, tool misuse, and encoding bypass attacks.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- 🔴 **6 attack modules** — Prompt Injection, Jailbreak, System Prompt Leak, PII Extraction, Tool Misuse, Encoding Bypass
- 🎯 **Multi-provider** — OpenAI, Anthropic, Ollama, custom OpenAI-compatible APIs
- 📊 **Professional reports** — Markdown output with severity scoring, evidence, and remediation
- 🧩 **Plugin architecture** — Add new attacks by subclassing `AttackModule`
- 📦 **Curated payloads** — 50+ jailbreak prompts, injection templates, PII probes in YAML

## Quick Start

```bash
# Clone
git clone https://github.com/YOU/llm-redteam-agent
cd llm-redteam-agent

# Install
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Set your API key
export OPENAI_API_KEY=sk-...

# Edit target in config.yaml, then:
python src/cli.py
```

## Demo

```bash
# Run against Ollama (local, no API key needed)
# First pull a model:
ollama pull llama3.2

# Edit config.yaml: provider=ollama, model=llama3.2
python src/cli.py
```

## Architecture

```
Orchestrator
  ├── PromptInjectionAttack  →  Tests system prompt override
  ├── JailbreakAttack        →  Tests DAN, roleplay, token smuggling
  ├── SystemPromptLeakAttack →  Tests prompt extraction
  ├── PIIExtractionAttack    →  Tests training data leakage
  ├── ToolMisuseAttack       →  Tests function calling abuse
  └── EncodingBypassAttack   →  Tests Base64/ROT13/Unicode bypass
       │
       └── Target (OpenAI / Ollama / Anthropic adapter)
```

## Adding a New Attack

```python
from src.attack_base import AttackModule, AttackResult, Severity

class MyAttack(AttackModule):
    name = "my_attack"
    description = "What it tests"
    severity = Severity.HIGH

    async def run(self, target, payloads=None):
        response = await target.send("My malicious prompt")
        if "vulnerable" in response.text.lower():
            return AttackResult(
                attack_name=self.name,
                success=True,
                severity=self.severity,
                evidence="Model is vulnerable",
                prompt_used="My malicious prompt",
                response=response.text,
            )
        return AttackResult(
            attack_name=self.name,
            success=False,
            severity=Severity.INFO,
            evidence="Model is secure",
            prompt_used="My malicious prompt",
            response=response.text,
        )
```

## Roadmap

- [ ] HTML report output with charts
- [ ] Multi-turn conversation simulation
- [ ] Automated retry with temperature variation
- [ ] CI/CD integration (GitHub Actions)
- [ ] Benchmark mode (compare multiple models)
- [ ] Web UI dashboard

## License

MIT — use responsibly. Only test models you own or have explicit permission to assess.
