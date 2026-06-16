import asyncio
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.attack_base import AttackModule, AttackResult, Severity
from src.target import Target

console = Console()


class Orchestrator:
    def __init__(self, target: Target, modules: Optional[list[AttackModule]] = None):
        self.target = target
        self.modules = modules or self._discover_modules()

    def _discover_modules(self) -> list[AttackModule]:
        from src.attacks.prompt_injection import PromptInjectionAttack
        from src.attacks.jailbreak import JailbreakAttack
        from src.attacks.system_prompt_leak import SystemPromptLeakAttack
        from src.attacks.pii_extraction import PIIExtractionAttack
        from src.attacks.tool_misuse import ToolMisuseAttack
        from src.attacks.encoding_bypass import EncodingBypassAttack

        return [
            PromptInjectionAttack(),
            JailbreakAttack(),
            SystemPromptLeakAttack(),
            PIIExtractionAttack(),
            ToolMisuseAttack(),
            EncodingBypassAttack(),
        ]

    async def run_all(self) -> list[AttackResult]:
        console.print(f"\n[bold red]⚡ LLM Red Team Agent[/bold red]")
        console.print(f"[dim]Target: {self.target.model} @ {self.target.base_url}[/dim]")
        console.print(f"[dim]Modules: {len(self.modules)} attacks loaded[/dim]\n")

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for module in self.modules:
                task = progress.add_task(
                    f"[yellow]{module.name}[/yellow] — {module.description[:60]}...",
                    total=None,
                )
                try:
                    result = await module.run(self.target)
                    results.append(result)
                    icon = "🔴" if result.success else "🟢"
                    progress.update(task, description=f"{icon} {module.name}: {'VULN' if result.success else 'OK'}")
                except Exception as e:
                    results.append(AttackResult(
                        attack_name=module.name,
                        success=False,
                        severity=Severity.INFO,
                        evidence=f"Error: {e}",
                        prompt_used="N/A",
                        response=str(e),
                    ))
                    progress.update(task, description=f"⚠️  {module.name}: ERROR")

        return results

    @staticmethod
    def summarize(results: list[AttackResult]) -> dict:
        total = len(results)
        successful = sum(1 for r in results if r.success)
        by_severity = {}
        for r in results:
            if r.success:
                by_severity[r.severity.value] = by_severity.get(r.severity.value, 0) + 1

        return {
            "total": total,
            "successful": successful,
            "failed": total - successful,
            "by_severity": by_severity,
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
        }
