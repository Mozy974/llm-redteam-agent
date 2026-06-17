import asyncio
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from src.attack_base import AttackModule, AttackResult, Severity
from src.target import Target
from src.judge import LLMJudge

console = Console()


class Orchestrator:
    def __init__(
        self,
        target: Target,
        modules: Optional[list[AttackModule]] = None,
        judge: Optional[LLMJudge] = None,
        concurrency: int = 1,
        fast_scan: bool = False,
        fast_limit: int = 3,
    ):
        self.target = target
        self.modules = modules or self._discover_modules()
        self.judge = judge
        self.concurrency = concurrency
        self.fast_scan = fast_scan
        self.fast_limit = fast_limit

    def _discover_modules(self) -> list[AttackModule]:
        from src.attacks.prompt_injection import PromptInjectionAttack
        from src.attacks.jailbreak import JailbreakAttack
        from src.attacks.system_prompt_leak import SystemPromptLeakAttack
        from src.attacks.pii_extraction import PIIExtractionAttack
        from src.attacks.tool_misuse import ToolMisuseAttack
        from src.attacks.encoding_bypass import EncodingBypassAttack
        from src.attacks.crescendo import CrescendoAttack

        return [
            PromptInjectionAttack(),
            JailbreakAttack(),
            SystemPromptLeakAttack(),
            PIIExtractionAttack(),
            ToolMisuseAttack(),
            EncodingBypassAttack(),
            CrescendoAttack(),
        ]

    async def run_all(self) -> list[AttackResult]:
        judge_status = "enabled" if (self.judge and self.judge.enabled) else "disabled"
        mode_parts = []
        if self.fast_scan:
            mode_parts.append(f"fast (top {self.fast_limit})")
        if self.concurrency > 1:
            mode_parts.append(f"concurrency={self.concurrency}")
        mode_str = f" [{', '.join(mode_parts)}]" if mode_parts else ""

        console.print(f"\n[bold red]⚡ LLM Red Team Agent[/bold red]{mode_str}")
        console.print(f"[dim]Target: {self.target.model} @ {self.target.base_url}[/dim]")
        console.print(f"[dim]Judge: {judge_status} (threshold: {self.judge.threshold if self.judge else 'N/A'})[/dim]")
        console.print(f"[dim]Modules: {len(self.modules)} attacks loaded[/dim]\n")

        if self.concurrency > 1:
            return await self._run_concurrent()
        else:
            return await self._run_sequential()

    async def _run_sequential(self) -> list[AttackResult]:
        """Original sequential execution with progress bar."""
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
                    result = await module.run(
                        self.target,
                        judge=self.judge,
                        max_payloads=self.fast_limit if self.fast_scan else None,
                    )
                    results.append(result)
                    icon = "🔴" if result.success else "🟢"
                    tags = []
                    if result.judge_used:
                        tags.append("[dim](judge)[/dim]")
                    if result.multi_turn:
                        tags.append(f"[dim]({result.turn_count}t)[/dim]")
                    tag_str = " " + " ".join(tags) if tags else ""
                    progress.update(
                        task,
                        description=f"{icon} {module.name}: {'VULN' if result.success else 'OK'}{tag_str}",
                    )
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

    async def _run_concurrent(self) -> list[AttackResult]:
        """Parallel execution for cloud APIs — all modules run simultaneously."""
        console.print(f"[dim]Running {len(self.modules)} modules in parallel (concurrency={self.concurrency})...[/dim]\n")

        async def run_one(module: AttackModule) -> AttackResult:
            try:
                return await module.run(
                    self.target,
                    judge=self.judge,
                    max_payloads=self.fast_limit if self.fast_scan else None,
                )
            except Exception as e:
                return AttackResult(
                    attack_name=module.name,
                    success=False,
                    severity=Severity.INFO,
                    evidence=f"Error: {e}",
                    prompt_used="N/A",
                    response=str(e),
                )

        # Use semaphore to limit actual concurrency
        sem = asyncio.Semaphore(self.concurrency)

        async def run_with_limit(module: AttackModule) -> AttackResult:
            async with sem:
                return await run_one(module)

        tasks = [run_with_limit(m) for m in self.modules]
        results = await asyncio.gather(*tasks)

        # Print results after all complete
        for r in results:
            icon = "🔴" if r.success else "🟢"
            tags = []
            if r.judge_used:
                tags.append("(judge)")
            if r.multi_turn:
                tags.append(f"({r.turn_count}t)")
            tag_str = " " + " ".join(tags) if tags else ""
            console.print(f"  {icon} {r.attack_name}: {'VULN' if r.success else 'OK'}{tag_str}")

        return results

    @staticmethod
    def summarize(results: list[AttackResult]) -> dict:
        total = len(results)
        successful = sum(1 for r in results if r.success)
        judge_assisted = sum(1 for r in results if r.judge_used)
        multi_turn = sum(1 for r in results if r.multi_turn)
        by_severity = {}
        for r in results:
            if r.success:
                by_severity[r.severity.value] = by_severity.get(r.severity.value, 0) + 1

        return {
            "total": total,
            "successful": successful,
            "failed": total - successful,
            "judge_assisted": judge_assisted,
            "multi_turn_attacks": multi_turn,
            "by_severity": by_severity,
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
        }
