#!/usr/bin/env python3
"""LLM Red Team Agent — CLI entry point.

Usage:
    python src/cli.py              # Full scan
    python src/cli.py --fast       # Fast scan (top-3 payloads per module)
    python src/cli.py --fast=5     # Fast scan with custom limit
"""

import asyncio
import os
import sys
from pathlib import Path
import yaml
from rich.console import Console
from rich.table import Table

from src.target import OpenAITarget, OllamaTarget
from src.orchestrator import Orchestrator
from src.report import ReportGenerator
from src.judge import LLMJudge

console = Console()


def parse_cli_flags() -> dict:
    """Parse --fast[=N] and other CLI flags from sys.argv."""
    flags = {"fast": False, "fast_limit": 3}
    for arg in sys.argv[1:]:
        if arg == "--fast":
            flags["fast"] = True
        elif arg.startswith("--fast="):
            flags["fast"] = True
            try:
                flags["fast_limit"] = int(arg.split("=", 1)[1])
            except ValueError:
                console.print("[yellow]Invalid --fast value, using default 3[/yellow]")
    return flags


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def build_target(config: dict):
    t = config["target"]
    provider = t["provider"]

    if provider == "openai":
        api_key = os.getenv(t.get("api_key_env", "OPENAI_API_KEY"))
        if not api_key:
            console.print("[red]Error:[/red] OPENAI_API_KEY not set")
            sys.exit(1)
        return OpenAITarget(
            base_url=t["base_url"],
            model=t["model"],
            api_key=api_key,
        )
    elif provider == "ollama":
        return OllamaTarget(
            base_url=t.get("base_url", "http://localhost:11434"),
            model=t["model"],
        )
    else:
        console.print(f"[red]Unknown provider:[/red] {provider}")
        sys.exit(1)


def build_judge(config: dict) -> LLMJudge | None:
    """Build the LLM judge from config, or return None if disabled."""
    j = config.get("judge", {})
    if not j.get("enabled", False):
        console.print("[dim]Judge: disabled (heuristics only)[/dim]")
        return None

    provider = j.get("provider", "ollama")
    base_url = j.get("base_url", "http://localhost:11434")
    model = j.get("model", "llama3.2")
    threshold = j.get("confidence_threshold", 0.75)

    if provider == "ollama":
        judge_target = OllamaTarget(base_url=base_url, model=model)
    elif provider == "openai":
        api_key = os.getenv(j.get("api_key_env", "JUDGE_API_KEY"))
        if not api_key:
            console.print("[yellow]Warning:[/yellow] JUDGE_API_KEY not set — judge disabled")
            return None
        judge_target = OpenAITarget(base_url=base_url, model=model, api_key=api_key)
    else:
        console.print(f"[yellow]Unknown judge provider:[/yellow] {provider} — judge disabled")
        return None

    console.print(f"[dim]Judge: {model} @ {base_url} (threshold: {threshold})[/dim]")
    return LLMJudge(target=judge_target, confidence_threshold=threshold, enabled=True)


async def main():
    cli_flags = parse_cli_flags()
    config = load_config()

    # Merge CLI flags with config
    fast_scan = cli_flags["fast"] or config.get("execution", {}).get("fast_scan", False)
    fast_limit = cli_flags["fast_limit"] if cli_flags["fast"] else config.get("execution", {}).get("fast_payload_limit", 3)
    concurrency = config.get("execution", {}).get("concurrency", 1)

    version = "0.4.0"
    mode_parts = []
    if fast_scan:
        mode_parts.append(f"fast (top {fast_limit})")
    if concurrency > 1:
        mode_parts.append(f"concurrency={concurrency}")
    mode_str = f" [{', '.join(mode_parts)}]" if mode_parts else ""

    console.print(f"[bold red]⚡ LLM Red Team Agent v{version}{mode_str}[/bold red]\n")

    target = build_target(config)
    judge = build_judge(config)
    orch = Orchestrator(
        target=target,
        judge=judge,
        concurrency=concurrency,
        fast_scan=fast_scan,
        fast_limit=fast_limit,
    )

    results = await orch.run_all()

    # Summary table
    summary = Orchestrator.summarize(results)
    table = Table(title="Scan Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")
    table.add_row("Total attacks", str(summary["total"]))
    table.add_row("🔴 Vulnerabilities found", str(summary["successful"]))
    table.add_row("✅ Passed", str(summary["failed"]))
    if summary.get("judge_assisted", 0) > 0:
        table.add_row("🧠 Judge-assisted detections", str(summary["judge_assisted"]))
    if summary.get("multi_turn_attacks", 0) > 0:
        table.add_row("🔄 Multi-turn attacks", str(summary["multi_turn_attacks"]))
    table.add_row("Critical", str(summary["critical"]))
    table.add_row("High", str(summary["high"]))
    console.print(table)

    # Generate report
    report_md = ReportGenerator.generate_markdown(
        results=results,
        target_model=target.model,
        target_url=target.base_url,
    )
    report_path = ReportGenerator.save_report(
        report_md,
        output_dir=config.get("report", {}).get("output_dir", "reports"),
    )
    console.print(f"\n[green]Report saved:[/green] {report_path}")

    # Exit code: 1 if any critical/high vulns found
    if summary["critical"] > 0 or summary["high"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
