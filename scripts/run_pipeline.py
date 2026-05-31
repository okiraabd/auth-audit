"""
scripts/run_pipeline.py — End-to-end pipeline runner.

Runs the full auth-audit pipeline (Tier 1 → 2 → 3) for all domains in the
configured input file, then writes the JSON and HTML reports.

Usage:
    python scripts/run_pipeline.py
    python scripts/run_pipeline.py --input data/my_hosts.json
    python scripts/run_pipeline.py --input data/my_hosts.json --output-dir output/run1
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich import box

# Ensure src/ is on the path (for running directly, not via pytest)
SRC = Path(__file__).parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from config import settings
from orchestration.pipeline import run_pipeline
from reporting.json_report import write_json_report
from reporting.html_report import generate_report

console = Console()

_VERDICT_EMOJI = {
    "PROTECTED":         "🔒",
    "PARTIAL":           "⚠️ ",
    "OPEN":              "🔓",
    "OPEN_API":          "🔓",
    "OPEN_API_CRITICAL": "🚨",
    "OPEN_DOCS":         "📄",
    "GRAPHQL_OPEN":      "🔓",
    "GRAPHQL_CRITICAL":  "🚨",
    "UNREACHABLE":       "💀",
    "UNKNOWN":           "❓",
}

_VERDICT_COLOR = {
    "PROTECTED":         "green",
    "PARTIAL":           "yellow",
    "OPEN":              "blue",
    "OPEN_API":          "orange1",
    "OPEN_API_CRITICAL": "red",
    "OPEN_DOCS":         "magenta",
    "GRAPHQL_OPEN":      "orange1",
    "GRAPHQL_CRITICAL":  "red",
    "UNREACHABLE":       "dim",
    "UNKNOWN":           "dim",
}


def _print_results_table(results) -> None:
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title=f"[bold]Auth Audit Results — {len(results)} domains[/bold]",
    )
    table.add_column("Domain", style="bold", max_width=40)
    table.add_column("Verdict", min_width=18)
    table.add_column("Service", style="dim", min_width=10)
    table.add_column("Conf", justify="right", min_width=4)
    table.add_column("Tier", justify="center", min_width=4)
    table.add_column("Review", justify="center", min_width=6)

    for r in results:
        v = r.final_verdict.value
        color = _VERDICT_COLOR.get(v, "dim")
        emoji = _VERDICT_EMOJI.get(v, "❓")
        review = "⚑" if r.needs_manual_review else ""
        table.add_row(
            r.domain,
            f"[{color}]{emoji} {v}[/{color}]",
            r.service_type.value,
            f"{r.confidence}%",
            f"T{r.tier_reached}",
            review,
        )

    console.print(table)


def _print_summary(results) -> None:
    counts: dict[str, int] = {}
    for r in results:
        v = r.final_verdict.value
        counts[v] = counts.get(v, 0) + 1

    lines = [f"[bold]Total:[/bold] {len(results)} domains\n"]
    for verdict, count in sorted(counts.items(), key=lambda x: -x[1]):
        color = _VERDICT_COLOR.get(verdict, "dim")
        emoji = _VERDICT_EMOJI.get(verdict, "❓")
        lines.append(f"  [{color}]{emoji} {verdict}[/{color}]: [bold]{count}[/bold]")

    critical = sum(1 for r in results if r.is_critical)
    needs_review = sum(1 for r in results if r.needs_manual_review)
    if critical:
        lines.append(f"\n  [red bold]🚨 {critical} CRITICAL exposure(s) found![/red bold]")
    if needs_review:
        lines.append(f"  [yellow]⚑  {needs_review} domain(s) need manual review[/yellow]")

    console.print(Panel("\n".join(lines), title="Summary", border_style="cyan"))


async def main() -> int:
    parser = argparse.ArgumentParser(description="auth-audit — Authentication Detection Pipeline")
    parser.add_argument("--input", "-i", help="Path to proxy_hosts JSON input file")
    parser.add_argument("--output-dir", "-o", help="Override output directory")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--no-hermes", action="store_true", help="Skip Tier 3 Hermes escalation")
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=args.log_level,
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
        format="%(message)s",
    )

    # Override settings if args provided
    if args.output_dir:
        out = Path(args.output_dir)
        settings.output_dir = out
        settings.results_json = out / "results.json"
        settings.results_jsonl = out / "results.jsonl"
        settings.results_html = out / "results.html"

    console.print(Panel(
        f"[bold cyan]auth-audit[/bold cyan] — Authentication Detection Pipeline\n"
        f"[dim]Input:  {args.input or settings.proxy_hosts_file}\n"
        f"Output: {settings.output_dir}[/dim]",
        border_style="cyan",
    ))

    # Run the pipeline
    results = await run_pipeline(input_file=args.input)

    if not results:
        console.print("[red]No results — check your input file.[/red]")
        return 1

    # Print results table
    _print_results_table(results)
    _print_summary(results)

    # Write JSON report
    write_json_report(results, settings.results_json)
    console.print(f"[green]✓ JSON report:[/green] {settings.results_json}")

    # Write HTML report
    generate_report(results, settings.results_html)
    console.print(f"[green]✓ HTML report:[/green] {settings.results_html}")

    # Upload HTML report to S3 if configured
    if settings.s3_enabled:
        try:
            s3_client = boto3.client(
                "s3",
                endpoint_url=settings.s3_endpoint,
                aws_access_key_id=settings.s3_access_key,
                aws_secret_access_key=settings.s3_secret_key,
                region_name="us-east-1",
                config=Config(connect_timeout=10, read_timeout=30)
            )
            
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            base_prefix = settings.s3_report_prefix.rstrip('/')
            
            run_key_html = f"{base_prefix}/run_{timestamp}/results.html"
            run_key_json = f"{base_prefix}/run_{timestamp}/results.json"
            latest_key_html = f"{base_prefix}/latest/results.html"
            
            console.print(f"[dim]Uploading reports to S3 ({settings.s3_bucket}/{base_prefix}/run_{timestamp}/)...[/dim]")
            
            # Helper to run blocking upload
            def _upload_files():
                s3_client.upload_file(str(settings.results_html), settings.s3_bucket, run_key_html, ExtraArgs={"ContentType": "text/html"})
                s3_client.upload_file(str(settings.results_json), settings.s3_bucket, run_key_json, ExtraArgs={"ContentType": "application/json"})
                s3_client.upload_file(str(settings.results_html), settings.s3_bucket, latest_key_html, ExtraArgs={"ContentType": "text/html"})
            
            await asyncio.to_thread(_upload_files)
            
            public_url = settings.s3_screenshot_url(latest_key_html)
            console.print(f"[bold green]✓ Report available at:[/bold green] {public_url}")
        except Exception as e:
            console.print(f"[bold red]✗ Failed to upload report to S3:[/bold red] {e}")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
