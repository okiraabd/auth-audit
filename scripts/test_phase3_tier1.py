#!/usr/bin/env python3
"""
scripts/test_phase3_tier1.py — Functional test for Phase 3: full Tier 1 pipeline.

Runs the complete Tier 1 pipeline on a domain or JSON file:
  1. Load domains (if --input) or build a single Domain (if --domain)
  2. Probe each domain with the async HTTP prober (Phase 2)
  3. Extract signals from probe results (Phase 3 — signal_extractor)
  4. Run the deterministic rule engine (Phase 3 — rule_engine)
  5. Display a rich verdict summary

Usage:
    python scripts/test_phase3_tier1.py --domain ima.ebdesk.com
    python scripts/test_phase3_tier1.py --domain ima.ebdesk.com --scheme http
    python scripts/test_phase3_tier1.py --input data/proxy_hosts.json
    python scripts/test_phase3_tier1.py --domain ima.ebdesk.com --json
    python scripts/test_phase3_tier1.py --domain ima.ebdesk.com --verbose
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
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import print as rprint

from models.domain import Domain
from models.probes import ProbeSet
from prober.http_prober import probe_all
from tier1.signal_extractor import extract_signals
from tier1.rule_engine import evaluate

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Phase 3 functional test — full Tier 1 pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", "-d", metavar="FQDN", help="Single domain to analyse")
    group.add_argument("--input", "-i", metavar="FILE", help="Proxy host JSON file")
    p.add_argument("--scheme", choices=["https", "http"], default="https")
    p.add_argument("--json", action="store_true", help="Output raw JSON")
    p.add_argument("--verbose", "-v", action="store_true", help="Show per-probe details too")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Verdict display helpers
# ---------------------------------------------------------------------------

_VERDICT_STYLES: dict[str, str] = {
    "PROTECTED": "bold green",
    "PARTIAL": "bold yellow",
    "OPEN": "bold red",
    "OPEN_API": "bold red",
    "OPEN_API_CRITICAL": "bold red reverse",
    "OPEN_DOCS": "red",
    "GRAPHQL_OPEN": "bold red",
    "GRAPHQL_CRITICAL": "bold red reverse",
    "UNREACHABLE": "dim",
    "UNKNOWN": "yellow",
}

_SERVICE_STYLES: dict[str, str] = {
    "WEB_APP": "blue",
    "REST_API": "green",
    "GRAPHQL": "magenta",
    "MIXED": "cyan",
    "UNKNOWN": "dim",
}

_VERDICT_ICONS: dict[str, str] = {
    "PROTECTED": "🔒",
    "PARTIAL": "⚠️ ",
    "OPEN": "🔓",
    "OPEN_API": "🔓",
    "OPEN_API_CRITICAL": "🚨",
    "OPEN_DOCS": "📄",
    "GRAPHQL_OPEN": "🔓",
    "GRAPHQL_CRITICAL": "🚨",
    "UNREACHABLE": "💀",
    "UNKNOWN": "❓",
}


def _verdict_text(verdict: str) -> str:
    style = _VERDICT_STYLES.get(verdict, "white")
    icon = _VERDICT_ICONS.get(verdict, "•")
    return f"[{style}]{icon} {verdict}[/{style}]"


def _service_text(stype: str) -> str:
    style = _SERVICE_STYLES.get(stype, "dim")
    return f"[{style}]{stype}[/{style}]"


def print_tier1_result(
    domain: str,
    probe_set: ProbeSet,
    signals: list[str],
    rule_output: dict,
    verbose: bool,
) -> None:
    verdict = rule_output["rule_verdict"]
    score = rule_output["rule_score"]
    stype = rule_output["service_type_guess"]
    triggered = rule_output["triggered_rules"]
    needs_llm = rule_output["needs_llm"]
    reason = rule_output.get("ambiguity_reason") or ""

    # ---- Header panel ----
    score_bar = "█" * (score // 10) + "░" * (10 - score // 10)
    needs_llm_str = "[yellow]→ Tier 2 LLM[/yellow]" if needs_llm else "[dim]no escalation[/dim]"

    header_lines = [
        f"[bold]Domain:[/bold]     [cyan]{domain}[/cyan]",
        f"[bold]Verdict:[/bold]    {_verdict_text(verdict)}",
        f"[bold]Service:[/bold]    {_service_text(stype)}",
        f"[bold]Confidence:[/bold] {score:3d}/100  [dim]{score_bar}[/dim]",
        f"[bold]Escalation:[/bold] {needs_llm_str}",
    ]
    if reason:
        header_lines.append(f"[bold]Reason:[/bold]     [italic dim]{reason}[/italic dim]")

    panel_style = _VERDICT_STYLES.get(verdict, "white").replace("reverse", "").strip()
    console.print(
        Panel(
            "\n".join(header_lines),
            title=f"[bold]Tier 1 Result — {domain}[/bold]",
            border_style=panel_style.split()[0] if panel_style else "white",
            padding=(0, 2),
        )
    )

    # ---- Signals ----
    if signals:
        sig_groups = {
            "Auth": [s for s in signals if any(s.startswith(p) for p in ("R_401", "R_403", "R_AUTH", "R_PASSWORD", "R_LOGIN", "R_SESSION"))],
            "Service": [s for s in signals if any(s.startswith(p) for p in ("R_JSON", "R_HTML", "R_GRAPHQL"))],
            "Docs/Risk": [s for s in signals if any(s.startswith(p) for p in ("R_OPEN", "R_SWAGGER", "R_OPENAPI", "R_REDOC", "R_SENSITIVE"))],
            "Other": [s for s in signals if s not in {sig for grp in ["Auth", "Service", "Docs/Risk"] for sig in []}],
        }
        # Flatten ungrouped
        grouped = set(sig for grp in list(sig_groups.values()) for sig in grp)
        sig_groups["Other"] = [s for s in signals if s not in grouped]
        if sig_groups["Other"] == signals:
            sig_groups = {"All": signals}

        console.print("\n  [bold]Signals extracted:[/bold]")
        for group, sigs in sig_groups.items():
            if sigs:
                formatted = "  ".join(f"[cyan]{s}[/cyan]" for s in sigs)
                console.print(f"    [dim]{group:8s}[/dim]  {formatted}")
    else:
        console.print("\n  [dim]No signals extracted.[/dim]")

    if triggered:
        trigs = "  ".join(f"[bold yellow]{t}[/bold yellow]" for t in triggered)
        console.print(f"\n  [bold]Triggered rules:[/bold]  {trigs}")

    # ---- Verbose probe table ----
    if verbose:
        console.print()
        table = Table(
            title="Probe Details",
            show_header=True,
            header_style="bold",
            border_style="dim",
            row_styles=["", "dim"],
        )
        table.add_column("Path", style="cyan", no_wrap=True)
        table.add_column("Status", width=7, justify="center")
        table.add_column("Content-Type")
        table.add_column("ms", width=7, justify="right")
        table.add_column("Redirects", width=9, justify="right")
        table.add_column("Note", overflow="fold")

        for probe in probe_set.probes:
            if probe.error:
                table.add_row(probe.path, "[red]ERR[/red]", "—", "—", "—", f"[dim red]{probe.error[:60]}[/dim red]")
            else:
                sc = probe.status_code or 0
                sc_style = "green" if sc < 300 else ("yellow" if sc < 400 else "red")
                ct = (probe.content_type or "").split(";")[0]
                note = probe.final_url if probe.final_url != probe.requested_url else "[dim]—[/dim]"
                table.add_row(
                    probe.path,
                    f"[{sc_style}]{sc}[/{sc_style}]",
                    ct or "[dim]—[/dim]",
                    f"{probe.response_time_ms:.0f}",
                    str(probe.redirect_count),
                    f"[dim]{note[:60]}[/dim]",
                )
        console.print(table)

    console.print()


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


async def run(args: argparse.Namespace) -> int:
    # --- Build domain list ---
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

    console.rule("[bold blue]Phase 3 — Full Tier 1 Pipeline[/bold blue]")
    console.print(f"Probing + analysing [bold]{len(domains)}[/bold] domain(s)...\n")

    # --- Phase 2: Probe ---
    probe_sets: list[ProbeSet] = await probe_all(domains)

    # --- Phase 3: Signals + Rules ---
    all_results = []
    for ps in probe_sets:
        signals = extract_signals(ps)
        rule_output = evaluate(signals, ps)
        all_results.append({
            "domain": ps.domain,
            "probe_set": ps,
            "signals": signals,
            "rule_output": rule_output,
        })

    # --- Output ---
    if args.json:
        output = []
        for r in all_results:
            output.append({
                "domain": r["domain"],
                "signals": r["signals"],
                "rule_engine": r["rule_output"],
                "probe_summary": r["probe_set"].compact_summary(),
            })
        print(json.dumps(output, indent=2, default=str))
        return 0

    for r in all_results:
        print_tier1_result(
            domain=r["domain"],
            probe_set=r["probe_set"],
            signals=r["signals"],
            rule_output=r["rule_output"],
            verbose=args.verbose,
        )

    # --- Summary table (multi-domain) ---
    if len(all_results) > 1:
        console.rule("[bold]Summary[/bold]")
        summary_table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
        )
        summary_table.add_column("Domain", style="cyan")
        summary_table.add_column("Verdict", justify="center")
        summary_table.add_column("Service", justify="center")
        summary_table.add_column("Score", justify="right", width=7)
        summary_table.add_column("→ Tier2", justify="center", width=8)
        summary_table.add_column("Signals", justify="right", width=8)

        for r in all_results:
            ro = r["rule_output"]
            verdict = ro["rule_verdict"]
            style = _VERDICT_STYLES.get(verdict, "white").split()[0]
            summary_table.add_row(
                r["domain"],
                f"[{style}]{verdict}[/{style}]",
                ro["service_type_guess"],
                str(ro["rule_score"]),
                "[yellow]YES[/yellow]" if ro["needs_llm"] else "[dim]no[/dim]",
                str(len(r["signals"])),
            )

        console.print(summary_table)

        needs_llm_count = sum(1 for r in all_results if r["rule_output"]["needs_llm"])
        console.print(
            f"\n[dim]Domains needing Tier 2 LLM:[/dim] "
            f"[yellow]{needs_llm_count}[/yellow] / {len(all_results)}"
        )

    return 0


def main() -> int:
    args = parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
