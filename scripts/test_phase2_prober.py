#!/usr/bin/env python3
"""
scripts/test_phase2_prober.py — Functional test for Phase 2: async HTTP prober.

Probes a single domain (or all domains from a JSON file) across all configured
paths and displays a rich, colour-coded result table.

Usage:
    python scripts/test_phase2_prober.py --domain ima.ebdesk.com
    python scripts/test_phase2_prober.py --domain ima.ebdesk.com --scheme http
    python scripts/test_phase2_prober.py --input data/proxy_hosts.json
    python scripts/test_phase2_prober.py --domain ima.ebdesk.com --json
"""

from __future__ import annotations

import argparse
import asyncio
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
from rich.panel import Panel
from rich import print as rprint

from models.domain import Domain
from models.probes import ProbeSet
from prober.http_prober import probe_all

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Phase 2 functional test — async HTTP prober",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--domain", "-d",
        metavar="FQDN",
        help="Single domain to probe (e.g. ima.ebdesk.com)",
    )
    group.add_argument(
        "--input", "-i",
        metavar="FILE",
        help="Proxy host JSON file — probes all enabled domains",
    )
    p.add_argument(
        "--scheme",
        choices=["https", "http"],
        default="https",
        help="Probe scheme when using --domain (default: https)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of Rich tables",
    )
    return p.parse_args()


def _status_style(code: int | None) -> str:
    if code is None:
        return "red"
    if code < 300:
        return "green"
    if code < 400:
        return "yellow"
    if code == 401:
        return "bold red"
    if code == 403:
        return "red"
    return "dim red"


def print_probe_set(ps: ProbeSet) -> None:
    console.rule(f"[bold cyan]{ps.domain}[/bold cyan]")

    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        row_styles=["", "dim"],
        expand=True,
    )
    table.add_column("Path", style="cyan", no_wrap=True)
    table.add_column("Cat", width=8, justify="center")
    table.add_column("Status", width=8, justify="center")
    table.add_column("Content-Type", no_wrap=True)
    table.add_column("Redirects", width=9, justify="right")
    table.add_column("Time (ms)", width=10, justify="right")
    table.add_column("Final URL / Error", overflow="fold")

    for probe in ps.probes:
        if probe.error:
            status_cell = "[red]ERR[/red]"
            final_cell = f"[dim red]{probe.error[:80]}[/dim red]"
            ct_cell = "—"
        else:
            style = _status_style(probe.status_code)
            status_cell = f"[{style}]{probe.status_code}[/{style}]"
            ct_cell = (probe.content_type or "").split(";")[0] or "[dim]—[/dim]"
            if probe.final_url != probe.requested_url:
                final_cell = f"[dim]{probe.final_url[:80]}[/dim]"
            else:
                final_cell = "[dim]—[/dim]"

        cat_colors = {"web": "blue", "api": "green", "docs": "yellow", "graphql": "magenta"}
        cat = probe.path_category
        cat_cell = f"[{cat_colors.get(cat, 'dim')}]{cat}[/{cat_colors.get(cat, 'dim')}]"

        table.add_row(
            probe.path,
            cat_cell,
            status_cell,
            ct_cell,
            str(probe.redirect_count) if not probe.error else "—",
            f"{probe.response_time_ms:.0f}" if not probe.error else "—",
            final_cell,
        )

    console.print(table)
    ok = ps.success_count
    total = ps.probe_count
    fail = total - ok
    console.print(
        f"  [green]✓ {ok} OK[/green]  "
        + (f"[red]✗ {fail} error(s)[/red]  " if fail else "")
        + f"[dim]{total} paths probed[/dim]\n"
    )


async def run(args: argparse.Namespace) -> int:
    # Build domain list
    if args.domain:
        try:
            from utils.urls import normalise_domain
            hostname = normalise_domain(args.domain)
        except ValueError as exc:
            console.print(f"[red]Invalid domain:[/red] {exc}")
            return 1
        domains = [Domain(hostname=hostname, probe_scheme=args.scheme)]
    else:
        from loaders.proxy_host_loader import load_domains
        try:
            domains = load_domains(args.input)
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[red]✗ {exc}[/red]")
            return 1
        if not domains:
            console.print("[yellow]⚠ No domains loaded.[/yellow]")
            return 0

    console.rule("[bold blue]Phase 2 — Async HTTP Prober[/bold blue]")
    console.print(f"Probing [bold]{len(domains)}[/bold] domain(s)...\n")

    probe_sets: list[ProbeSet] = await probe_all(domains)

    if args.json:
        output = [ps.model_dump(mode="json") for ps in probe_sets]
        print(json.dumps(output, indent=2, default=str))
        return 0

    for ps in probe_sets:
        print_probe_set(ps)

    return 0


def main() -> int:
    args = parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
