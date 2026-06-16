#!/usr/bin/env bash
# Demo: run red team scan against Ollama with llama3.2
set -euo pipefail

echo "⚡ LLM Red Team Agent — Demo"
echo "============================"
echo ""

# Check ollama
if ! command -v ollama &>/dev/null; then
    echo "Installing ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

# Pull model if needed
if ! ollama list | grep -q llama3.2; then
    echo "Pulling llama3.2..."
    ollama pull llama3.2
fi

cd "$(dirname "$0")/.."
source .venv/bin/activate 2>/dev/null || uv venv && source .venv/bin/activate
uv pip install -e ".[dev]" -q

python -c "
import asyncio, os
from src.target import OllamaTarget
from src.orchestrator import Orchestrator
from src.report import ReportGenerator

async def demo():
    target = OllamaTarget('http://localhost:11434', 'llama3.2')
    orch = Orchestrator(target=target)
    results = await orch.run_all()
    md = ReportGenerator.generate_markdown(results, 'llama3.2', 'http://localhost:11434')
    path = ReportGenerator.save_report(md)
    print(f'\\n✅ Report: {path}')

asyncio.run(demo())
"

echo ""
echo "Done! Check reports/ directory for the output."
