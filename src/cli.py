#!/usr/bin/env python3
"""LLM Red Team Agent — CLI entry point."""

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
    console.print("[bold red]⚡ LLM Red Team Agent v0.2.0[/bold red]\n")

    config = load_config()
    target = build_target(config)
    judge = build_judge(config)
    orch = Orchestrator(target=target, judge=judge)

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
