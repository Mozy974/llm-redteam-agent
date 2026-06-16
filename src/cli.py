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


async def main():
    console.print("[bold red]⚡ LLM Red Team Agent v0.1.0[/bold red]\n")

    config = load_config()
    target = build_target(config)
    orch = Orchestrator(target=target)

    results = await orch.run_all()

    # Summary table
    summary = Orchestrator.summarize(results)
    table = Table(title="Scan Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")
    table.add_row("Total attacks", str(summary["total"]))
    table.add_row("🔴 Vulnerabilities found", str(summary["successful"]))
    table.add_row("✅ Passed", str(summary["failed"]))
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
