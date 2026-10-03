"""
CodePulse AI - Main CLI Entrypoint
==================================
Command-line interface for multi-agent code security triage, benchmarking,
and launching the interactive web dashboard.
"""

import argparse
import os
import sys
import warnings
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

# Suppress minor warnings for clean CLI output
warnings.filterwarnings("ignore")

# Ensure project root is in path
root_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(root_dir))

from src.agents.orchestrator import AgentOrchestrator
from src.config import load_settings

console = Console()

BANNER = """[bold cyan]
   ______          __      ____        __            ___    ____
  / ____/___  ____/ /__   / __ \__  __/ /_______    /   |  /  _/
 / /   / __ \/ __  / _ \ / /_/ / / / / / ___/ _ \  / /| |  / /  
/ /___/ /_/ / /_/ /  __// ____/ /_/ / (__  )  __/ / ___ |_/ /   
\____/\____/\__,_/\___//_/    \__,_/_/____/\___/ /_/  |_/___/   
[/bold cyan]
[dim]Autonomous Multi-Agent Code Vulnerability Triage & Patch Synthesis Engine[/dim]
[cyan]NLP & LLM Systems Final Project | Production Grade[/cyan]
"""


def cli_scan(target_path: str, force_mock: bool = False, force_refresh: bool = False):
    console.print(BANNER)
    p = Path(target_path)
    if not p.exists():
        console.print(f"[bold red]Error:[/bold red] Target path '{target_path}' does not exist.")
        sys.exit(1)

    settings = load_settings()
    if force_mock:
        settings.llm.default_provider = "mock"

    orchestrator = AgentOrchestrator(settings)

    target_files = []
    if p.is_file():
        target_files.append(p)
    else:
        for ext in settings.parser.supported_extensions:
            target_files.extend(p.glob(f"**/*{ext}"))

    if not target_files:
        console.print(f"[yellow]No supported code files found in {target_path}[/yellow]")
        return

    console.print(f"[bold green]Scanning {len(target_files)} file(s) with Multi-Agent Pipeline...[/bold green]\n")

    for file_path in target_files:
        with console.status(f"[cyan]Analyzing AST & Executing Multi-Agent Triage on {file_path.name}...[/cyan]"):
            report = orchestrator.analyze_file(str(file_path), force_refresh=force_refresh)

        # File Overview Card
        status_color = "red" if report.overall_status == "VULNERABILITIES_CONFIRMED" else (
            "green" if report.overall_status == "CLEAN" else "yellow"
        )

        console.print(
            Panel(
                f"[bold]Target File:[/bold] [cyan]{file_path}[/cyan]\n"
                f"[bold]Language:[/bold] {report.language.title()} | [bold]Lines:[/bold] {report.total_lines}\n"
                f"[bold]Overall Status:[/bold] [{status_color}]{report.overall_status}[/{status_color}]\n"
                f"[bold]Dangerous Sinks Detected (AST):[/bold] {len(report.ast_metadata.get('dangerous_sinks', []))}\n"
                f"[bold]Sanitizers/Guards Detected (AST):[/bold] {len(report.ast_metadata.get('sanitizers', []))}",
                title=f"Security Audit: {file_path.name}",
                border_style=status_color,
            )
        )

        # Stage 1 & 2 Findings Table
        if report.audited_findings:
            table = Table(title="Audited Findings (Devil's Advocate Stage)", header_style="bold magenta")
            table.add_column("CWE", style="bold red")
            table.add_column("Verdict", style="bold")
            table.add_column("Confidence", justify="right")
            table.add_column("Audit Rationale", style="white")

            for finding in report.audited_findings:
                verdict_color = "green" if "REJECTED" in finding.verdict else ("red" if finding.verdict == "CONFIRMED" else "yellow")
                table.add_row(
                    finding.cwe_id,
                    f"[{verdict_color}]{finding.verdict}[/{verdict_color}]",
                    f"{finding.calibrated_confidence:.2f}",
                    finding.audit_rationale[:90] + ("..." if len(finding.audit_rationale) > 90 else ""),
                )
            console.print(table)

        # Stage 3 Patches
        if report.patches:
            for patch in report.patches:
                console.print(f"\n[bold green]⚡ Remediation Patch Synthesized ({patch.cwe_id}):[/bold green]")
                console.print(f"[dim]{patch.patch_summary}[/dim]")
                console.print(Syntax(patch.unified_diff, "diff", theme="monokai", line_numbers=True))

        # Telemetry Summary
        stats = report.summary_statistics
        console.print(
            Panel(
                f"Candidates Flagged: [cyan]{stats.get('total_candidates_flagged', 0)}[/cyan] | "
                f"Confirmed: [red]{stats.get('confirmed_vulnerabilities', 0)}[/red] | "
                f"False Positives Eliminated: [green]{stats.get('false_positives_eliminated', 0)} ({stats.get('false_positive_reduction_pct', 0)}%)[/green]\n"
                f"Tokens: {stats.get('total_tokens_consumed', 0):,} | "
                f"Cost: ${stats.get('total_cost_usd', 0):.6f} | "
                f"Latency: {stats.get('pipeline_latency_ms', 0)}ms",
                title="Stage Telemetry",
                border_style="dim",
            )
        )
        console.print("\n" + "=" * 70 + "\n")


def cli_bench(force_mock: bool = False):
    from evals.run_evals import run_benchmark
    run_benchmark(force_mock=force_mock)


def cli_web(host: str = "127.0.0.1", port: int = 8000, reload: bool = False):
    console.print(BANNER)
    console.print(f"[bold green]Starting CodePulse AI Interactive Dashboard at http://{host}:{port}...[/bold green]\n")
    import uvicorn
    uvicorn.run("web.app:app", host=host, port=port, reload=reload)


def main():
    parser = argparse.ArgumentParser(
        description="CodePulse AI: Multi-Agent Code Vulnerability Triage & Patch Synthesis Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory for security vulnerabilities")
    scan_parser.add_argument("path", help="Path to source file or directory to audit")
    scan_parser.add_argument("--mock", action="store_true", help="Force mock LLM provider (offline testing)")
    scan_parser.add_argument("--refresh", action="store_true", help="Bypass semantic cache and force fresh inference")

    # bench subcommand
    bench_parser = subparsers.add_parser("bench", help="Run automated benchmark against ground truth CWE corpus")
    bench_parser.add_argument("--mock", action="store_true", help="Force mock LLM provider for benchmark")

    # web subcommand
    web_parser = subparsers.add_parser("web", help="Launch the interactive web dashboard")
    web_parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    web_parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    web_parser.add_argument("--reload", action="store_true", help="Enable live reload for development")

    args = parser.parse_args()

    if args.command == "scan":
        cli_scan(args.path, force_mock=args.mock, force_refresh=args.refresh)
    elif args.command == "bench":
        cli_bench(force_mock=args.mock)
    elif args.command == "web":
        cli_web(host=args.host, port=args.port, reload=args.reload)
    else:
        # Default behavior: show banner & help
        console.print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
