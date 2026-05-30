"""
scripts/generate_html.py — Regenerate HTML report from JSONL checkpoint.

Usage:
    python scripts/generate_html.py --input output/results.jsonl
    python scripts/generate_html.py --input latest_checkpoint.jsonl --output output/recovered.html
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel

# Ensure src/ is on the path
SRC = Path(__file__).parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from config import settings
from models.result import DomainResult
from reporting.html_report import generate_report

console = Console()

def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HTML report from an existing JSONL file.")
    parser.add_argument("--input", "-i", required=True, help="Path to input .jsonl file")
    parser.add_argument("--output", "-o", default=str(settings.results_html), help="Path to output HTML file")
    parser.add_argument("--limit", "-n", type=int, default=0, help="Maximum number of domains to process (0 = all)")
    parser.add_argument("--upload-s3", action="store_true", help="Upload the generated HTML to S3")
    parser.add_argument("--s3-path", help="Custom S3 key/path to upload to (e.g. auth-audit/reports/custom.html)")
    parser.add_argument("--update-latest", action="store_true", help="Overwrite the main latest/results.html dashboard in S3")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
        format="%(message)s",
    )

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        console.print(f"[bold red]Error:[/bold red] Input file {input_path} does not exist.")
        return 1

    console.print(Panel(
        f"[bold cyan]HTML Generator[/bold cyan]\n"
        f"[dim]Input:  {input_path}\n"
        f"Output: {output_path}[/dim]",
        border_style="cyan",
    ))

    results: list[DomainResult] = []
    
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    res = DomainResult.model_validate_json(line)
                    results.append(res)
                except Exception as e:
                    logging.warning("Skipping invalid JSON line: %s", e)
                
                if args.limit > 0 and len(results) >= args.limit:
                    break
    except Exception as e:
        console.print(f"[bold red]Error reading input file:[/bold red] {e}")
        return 1

    if not results:
        console.print("[red]No valid domain results found in input file.[/red]")
        return 1

    console.print(f"Loaded {len(results)} domain results. Generating HTML...")
    
    # Generate HTML
    try:
        generate_report(results, output_path)
        console.print(f"[green]✓ HTML report successfully generated at:[/green] {output_path}")
    except Exception as e:
        console.print(f"[bold red]Error generating report:[/bold red] {e}")
        return 1

    # Upload to S3 if requested
    if args.upload_s3 and settings.s3_enabled:
        try:
            import boto3
            from botocore.config import Config
            s3_client = boto3.client(
                "s3",
                endpoint_url=settings.s3_endpoint,
                aws_access_key_id=settings.s3_access_key,
                aws_secret_access_key=settings.s3_secret_key,
                region_name="us-east-1",
                config=Config(connect_timeout=10, read_timeout=30)
            )
            
            base_prefix = settings.s3_report_prefix.rstrip('/')
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            
            # Determine primary S3 key
            if args.s3_path:
                run_key_html = args.s3_path
            else:
                run_key_html = f"{base_prefix}/recovered_{timestamp}/results.html"
                
            latest_key_html = f"{base_prefix}/latest/results.html"
            
            console.print(f"[dim]Uploading report to S3 ({settings.s3_bucket}/{run_key_html})...[/dim]")
            
            def _upload_files():
                s3_client.upload_file(str(output_path), settings.s3_bucket, run_key_html, ExtraArgs={"ContentType": "text/html"})
                if args.update_latest:
                    s3_client.upload_file(str(output_path), settings.s3_bucket, latest_key_html, ExtraArgs={"ContentType": "text/html"})
            
            # Since this is a synchronous script's main thread (not inside an asyncio loop like pipeline),
            # we can just run it synchronously, but since main() is not async here, wait, we are not in an async main().
            # Let's just run it synchronously!
            _upload_files()
            
            public_url = f"{settings.s3_endpoint.rstrip('/')}/{settings.s3_bucket}/{run_key_html}"
            console.print(f"[bold green]✓ Report available at:[/bold green] {public_url}")
            
            if args.update_latest:
                latest_url = settings.s3_screenshot_url(latest_key_html)
                console.print(f"[bold green]✓ Main dashboard updated at:[/bold green] {latest_url}")
                
        except Exception as e:
            console.print(f"[bold red]✗ Failed to upload report to S3:[/bold red] {e}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
