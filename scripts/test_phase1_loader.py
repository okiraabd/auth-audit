#!/usr/bin/env python3
"""
scripts/test_phase1_loader.py — Functional test for Phase 1: proxy host loader.

Loads a proxy host JSON file, runs the loader, and prints a Rich table of all
extracted domains with their inferred probe scheme and source metadata.

Usage:
    python scripts/test_phase1_loader.py
    python scripts/test_phase1_loader.py --input data/proxy_hosts.json
    python scripts/test_phase1_loader.py --input data/proxy_hosts.json --json
    python scripts/test_phase1_loader.py --include-disabled
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap — must happen before any src/ imports
# ---------------------------------------------------------------------------
_SRC = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(_SRC))

from rich.console import Console
from rich.table import Table
from rich import print as rprint

from loaders.proxy_host_loader import load_domains
from models.domain import Domain

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Phase 1 functional test — proxy host loader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--input", "-i",
        default="data/proxy_hosts.json",
        metavar="FILE",
        help="Path to the proxy host JSON file (default: data/proxy_hosts.json)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of a Rich table",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)

    console.rule("[bold blue]Phase 1 — Proxy Host Loader[/bold blue]")

    try:
        domains: list[Domain] = load_domains(input_path)
    except FileNotFoundError:
        console.print(f"[red]✗ File not found:[/red] {input_path}")
        return 1
    except ValueError as exc:
        console.print(f"[red]✗ Invalid input:[/red] {exc}")
        return 1

    if not domains:
        console.print("[yellow]⚠ No domains loaded (all entries may be disabled or invalid).[/yellow]")
        return 0

    if args.json:
        output = [
            {
                "hostname": d.hostname,
                "probe_scheme": d.probe_scheme,
                "probe_base_url": d.probe_base_url,
                "source_id": d.source_id,
            }
            for d in domains
        ]
        print(json.dumps(output, indent=2))
        return 0

    # Rich table output
    table = Table(
        title=f"[bold]Loaded Domains[/bold] from [cyan]{input_path}[/cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        row_styles=["", "dim"],
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Hostname", style="cyan", no_wrap=True)
    table.add_column("Scheme", justify="center", width=8)
    table.add_column("Probe URL", style="blue")
    table.add_column("Source ID", justify="right", width=10)

    for i, d in enumerate(domains, 1):
        scheme_color = "green" if d.probe_scheme == "https" else "yellow"
        table.add_row(
            str(i),
            d.hostname,
            f"[{scheme_color}]{d.probe_scheme}[/{scheme_color}]",
            d.probe_base_url,
            str(d.source_id) if d.source_id is not None else "[dim]—[/dim]",
        )

    console.print(table)
    console.print(
        f"\n[green]✓[/green] Loaded [bold]{len(domains)}[/bold] unique domain(s) "
        f"from [cyan]{input_path.name}[/cyan]"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
