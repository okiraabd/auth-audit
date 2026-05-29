"""
scripts/test_phase5_hermes.py — Functional test for the Hermes Browser Agent client.

Usage:
  python scripts/test_phase5_hermes.py --domain example.com
"""

import argparse
import asyncio
import json
import logging
from pathlib import Path

from models.domain import Domain
from tier3.hermes_client import HermesClient
from tier3.hermes_tasks import build_auth_check_task
from rich.console import Console
from rich.panel import Panel

logging.basicConfig(level=logging.WARNING)
console = Console()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Test Tier 3 Hermes Client")
    parser.add_argument("--domain", required=True, help="Domain to test")
    parser.add_argument("--reason", default="Manual testing trigger", help="Reason for escalation")
    args = parser.parse_args()

    domain = Domain(hostname=args.domain)
    console.print(f"[bold cyan]──────────────────────── Phase 5 — Tier 3 Hermes Agent ────────────────────────[/bold cyan]")
    
    # Use real Hermes configuration from env if available, else fallback to config defaults
    from config import settings
    console.print(f"Target Hermes endpoint: [yellow]{settings.hermes_base_url}[/yellow]")
    
    tier2_mock = {
        "verdict": "UNKNOWN",
        "service_type": "WEB_APP",
    }
    
    task_payload = build_auth_check_task(
        domain=domain.hostname,
        escalation_reason=args.reason,
        tier2_output=tier2_mock
    )

    console.print("\n[bold]Task Payload:[/bold]")
    console.print(json.dumps(task_payload, indent=2))
    
    console.print(f"\n[bold cyan]Submitting task to Hermes... (this may take up to 60s)[/bold cyan]")

    async with HermesClient() as client:
        result = await client.submit_task(task_payload)
        
    console.print("\n[bold]Hermes Result:[/bold]")
    
    verdict = result.get("verdict", "UNKNOWN")
    color = "red" if verdict == "PROTECTED" else "green" if verdict.startswith("OPEN") else "yellow"
    
    console.print(Panel(
        f"[bold]Verdict      :[/bold] [{color}]{verdict}[/{color}]\n"
        f"[bold]Confidence   :[/bold] {result.get('confidence')}\n"
        f"[bold]Evidence     :[/bold] {result.get('visual_evidence')}\n"
        f"[bold]Reasoning    :[/bold] {result.get('reasoning')}\n"
        f"[bold]Screenshots  :[/bold] {len(result.get('screenshots', []))} captured\n"
        f"[bold]Interactions :[/bold] {len(result.get('interaction_steps', []))} steps",
        title=f"Hermes Browser Agent — {domain.hostname}",
        expand=False
    ))
    
    if "_error" in result:
        console.print(f"\n[bold red]Error Details:[/bold red] {result['_error']}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted by user.[/bold red]")
