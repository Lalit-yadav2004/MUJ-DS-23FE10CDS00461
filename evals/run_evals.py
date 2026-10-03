"""
CodePulse AI - Automated Benchmark Evaluation Suite
===================================================
Runs precision/recall/F1 benchmarks across curated CWE vulnerability corpora
and validates multi-agent false positive elimination.
"""

import json
import sys
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from src.agents.orchestrator import AgentOrchestrator
from src.config import load_settings
from src.telemetry.metrics import TelemetryMetrics

console = Console()


def run_benchmark(force_mock: bool = False):
    console.print(
        Panel.fit(
            "[bold cyan]CodePulse AI[/bold cyan] — [bold green]Evaluation & Benchmark Harness[/bold green]\n"
            "[dim]Benchmarking Multi-Agent Triage against Ground Truth CWE Corpus[/dim]",
            border_style="cyan",
        )
    )

    settings = load_settings()
    if force_mock:
        settings.llm.default_provider = "mock"

    orchestrator = AgentOrchestrator(settings)
    evals_dir = root_dir / "evals"
    gt_path = evals_dir / "ground_truth.json"

    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    predictions = []
    results_table = Table(title="Corpus Test Results", header_style="bold magenta")
    results_table.add_column("File", style="cyan")
    results_table.add_column("Ground Truth", style="yellow")
    results_table.add_column("Hunter Stage", style="blue")
    results_table.add_column("Auditor Stage", style="green")
    results_table.add_column("Patches", justify="center")
    results_table.add_column("Latency (ms)", justify="right")

    start_bench = time.time()

    for item in ground_truth:
        rel_path = item["file_path"]
        full_path = root_dir / rel_path
        expected_vuln = item["is_vulnerable"]

        with open(full_path, "r", encoding="utf-8") as f:
            code_text = f.read()

        report = orchestrator.analyze_file(str(full_path), code_content=code_text, force_refresh=True)
        pred_dict = report.model_dump()
        pred_dict["file_path"] = rel_path
        predictions.append(pred_dict)

        cands_count = len(report.hunter_candidates)
        confirmed_count = sum(1 for f in report.audited_findings if f.verdict == "CONFIRMED")
        fp_count = sum(1 for f in report.audited_findings if f.verdict == "REJECTED_FALSE_POSITIVE")

        gt_badge = "[bold red]VULNERABLE[/bold red]" if expected_vuln else "[bold green]SAFE[/bold green]"
        hunter_badge = f"{cands_count} flagged"
        if confirmed_count > 0:
            auditor_badge = f"[red]{confirmed_count} Confirmed[/red]"
        elif fp_count > 0:
            auditor_badge = f"[green]{fp_count} FP Eliminated[/green]"
        else:
            auditor_badge = "[dim]Clean[/dim]"

        patch_badge = f"[bold cyan]{len(report.patches)}[/bold cyan]" if report.patches else "[dim]-[/dim]"
        lat_ms = report.summary_statistics.get("pipeline_latency_ms", 0)

        results_table.add_row(
            Path(rel_path).name,
            gt_badge,
            hunter_badge,
            auditor_badge,
            patch_badge,
            str(lat_ms),
        )

    console.print(results_table)

    # Compute aggregate metrics
    metrics = TelemetryMetrics.calculate_benchmark_metrics(ground_truth, predictions)
    bench_duration = round(time.time() - start_bench, 2)

    total_tokens = sum(
        p.get("summary_statistics", {}).get("total_tokens_consumed", 0) for p in predictions
    )
    total_cost = sum(
        p.get("summary_statistics", {}).get("total_cost_usd", 0.0) for p in predictions
    )

    metrics_table = Table(title="Aggregate Accuracy & Reliability Metrics", header_style="bold green")
    metrics_table.add_column("Metric", style="bold white")
    metrics_table.add_column("Score / Value", style="bold cyan")

    metrics_table.add_row("Precision", f"{metrics['precision'] * 100:.1f}%")
    metrics_table.add_row("Recall (Sensitivity)", f"{metrics['recall'] * 100:.1f}%")
    metrics_table.add_row("F1-Score", f"{metrics['f1_score'] * 100:.1f}%")
    metrics_table.add_row("Overall Accuracy", f"{metrics['accuracy'] * 100:.1f}%")
    metrics_table.add_row("False Positive Rate (FPR)", f"{metrics['false_positive_rate'] * 100:.1f}%")
    metrics_table.add_row("Total Benchmark Latency", f"{bench_duration}s")
    metrics_table.add_row("Total Tokens Consumed", f"{total_tokens:,}")
    metrics_table.add_row("Estimated API Cost", f"${total_cost:.6f}")

    console.print(metrics_table)

    # Save to JSON
    output_report = {
        "timestamp": time.time(),
        "aggregate_metrics": metrics,
        "total_files_evaluated": len(ground_truth),
        "total_tokens": total_tokens,
        "total_cost_usd": total_cost,
        "predictions": predictions,
    }
    report_file = evals_dir / "benchmark_results.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(output_report, f, indent=2)

    console.print(f"\n[bold green]✓ Benchmark complete! Report saved to:[/bold green] [dim]{report_file}[/dim]\n")
    return metrics


if __name__ == "__main__":
    force_mock = "--mock" in sys.argv
    run_benchmark(force_mock=force_mock)
