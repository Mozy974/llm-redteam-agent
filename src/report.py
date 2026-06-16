from datetime import datetime, timezone
from pathlib import Path
from src.attack_base import AttackResult, Severity
from src.orchestrator import Orchestrator


class ReportGenerator:
    @staticmethod
    def _severity_emoji(severity: Severity) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "🟢",
        }.get(severity, "⚪")

    @staticmethod
    def generate_markdown(
        results: list[AttackResult],
        target_model: str,
        target_url: str,
    ) -> str:
        summary = Orchestrator.summarize(results)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"# LLM Red Team Report",
            f"",
            f"**Target:** `{target_model}` @ `{target_url}`",
            f"**Date:** {now}",
            f"**Tool:** llm-redteam-agent v0.3.0",
            f"",
            f"---",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total attacks | {summary['total']} |",
            f"| Vulnerabilities found | {summary['successful']} |",
            f"| Passed (safe) | {summary['failed']} |",
            f"| 🔴 Critical | {summary['critical']} |",
            f"| 🟠 High | {summary['high']} |",
            f"| 🟡 Medium | {summary['medium']} |",
            f"| 🔵 Low | {summary['low']} |",
        ]

        if summary.get("judge_assisted", 0) > 0:
            lines.append(f"| 🧠 Judge-assisted | {summary['judge_assisted']} |")
        if summary.get("multi_turn_attacks", 0) > 0:
            lines.append(f"| 🔄 Multi-turn attacks | {summary['multi_turn_attacks']} |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Detailed Findings",
            f"",
        ])

        for r in results:
            emoji = ReportGenerator._severity_emoji(r.severity)
            status = "⚠️  VULNERABLE" if r.success else "✅ Secure"
            attack_type = ""
            if r.multi_turn:
                attack_type = f" [multi-turn · {r.turn_count} turns]"
            if r.judge_used:
                attack_type += " [judge-confirmed]"

            lines.extend([
                f"### {emoji} {r.attack_name} — {status}{attack_type}",
                f"",
                f"**Severity:** {r.severity.value}",
                f"**Description:** {r.evidence}",
                f"",
            ])

            if r.multi_turn and r.judge_verdict:
                jv = r.judge_verdict
                lines.extend([
                    f"**Escalation:** {'Successful' if jv.get('escalation_successful') else 'Not detected'}",
                    f"**Critical turn:** {jv.get('critical_turn', 'N/A')}",
                    f"**Judge confidence:** {jv.get('confidence', 'N/A')}",
                    f"",
                ])

            lines.extend([
                f"<details>",
                f"<summary>Payload & Response</summary>",
                f"",
                f"**Prompt used:**",
                f"```",
                f"{r.prompt_used[:500]}",
                f"```",
                f"",
                f"**Model response:**",
                f"```",
                f"{r.response[:1000]}",
                f"```",
                f"",
                f"</details>",
                f"",
                f"---",
                f"",
            ])

        lines.append("## Recommendations")
        lines.append("")
        if summary["successful"] > 0:
            lines.append("⚠️  **This model has security vulnerabilities.** Consider:")
            lines.append("")
            if summary["critical"] > 0:
                lines.append("- **Immediate:** Review and harden system prompt against injection")
                lines.append("- **Immediate:** Implement input sanitization for encoded payloads")
            if summary["high"] > 0:
                lines.append("- Strengthen guardrails against jailbreak attempts")
                lines.append("- Add PII detection in output layer")
            if summary.get("multi_turn_attacks", 0) > 0:
                lines.append("- **Critical:** Implement multi-turn escalation detection — the model is vulnerable to Crescendo-style attacks")
                lines.append("- Add conversation-level safety classifiers, not just per-message")
            lines.append("- Run red team assessments regularly after each model update")
        else:
            lines.append("✅ No vulnerabilities detected in this assessment run.")
            lines.append("")
            lines.append("- Continue periodic red team assessments")
            lines.append("- Monitor for new attack techniques as they emerge")

        return "\n".join(lines)

    @staticmethod
    def save_report(markdown: str, output_dir: str = "reports") -> Path:
        out = Path(output_dir)
        out.mkdir(exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = out / f"redteam_report_{ts}.md"
        path.write_text(markdown)
        return path
