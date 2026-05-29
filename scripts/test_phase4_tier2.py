#!/usr/bin/env python3
"""
scripts/test_phase4_tier2.py — Functional test for Phase 4: Tier 2 LLM Analysis.

Runs the pipeline through Tier 2:
  1. Load single domain (or all from JSON)
  2. Probe HTTP (Tier 1)
  3. Extract signals + rule engine (Tier 1)
  4. Summarize HTML + Call Local LLM (Tier 2) if needed
  5. Display rich Tier 2 verdict

Note: Requires Local LLM to be running locally or a valid Local LLM base URL/API key
in your .env file or environment variables.

Usage:
    python scripts/test_phase4_tier2.py --domain ima.ebdesk.com
    python scripts/test_phase4_tier2.py --input data/proxy_hosts.json
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

from models.domain import Domain
from models.probes import ProbeSet
from prober.http_prober import probe_all
from tier1.signal_extractor import extract_signals
from tier1.rule_engine import evaluate
from tier2.llm_analyzer import analyze_domain
from tier2.llm_client import LLMClient
from config import settings

console = Console()

# We can re-use the styles from Phase 3 test script
_VERDICT_STYLES = {
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

_VERDICT_ICONS = {
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


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 4 functional test — Tier 2 LLM")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", "-d", metavar="FQDN", help="Single domain to analyse")
    group.add_argument("--input", "-i", metavar="FILE", help="Proxy host JSON file")
    p.add_argument("--scheme", choices=["https", "http"], default="https")
    p.add_argument("--json", action="store_true", help="Output raw JSON")
    return p.parse_args()


def print_tier2_result(domain: str, llm_output: dict, tier1_output: dict) -> None:
    v_t1 = tier1_output["rule_verdict"]
    v_t2 = llm_output["verdict"]

    style_t1 = _VERDICT_STYLES.get(v_t1, "white")
    style_t2 = _VERDICT_STYLES.get(v_t2, "white")

    icon_t1 = _VERDICT_ICONS.get(v_t1, "•")
    icon_t2 = _VERDICT_ICONS.get(v_t2, "•")

    score_t1 = tier1_output["rule_score"]
    score_t2 = llm_output["confidence"]

    needs_llm = tier1_output["needs_llm"]
    escalated = "Yes" if needs_llm else "No (bypassed)"
    
    needs_browser = llm_output["needs_browser_escalation"]
    browser_str = "[bold red]YES[/bold red]" if needs_browser else "[dim]no[/dim]"

    auth_mechs = ", ".join(llm_output.get("auth_mechanisms_detected", [])) or "None detected"
    
    lines = [
        f"[bold]Tier 1 Verdict :[/bold] [{style_t1}]{icon_t1} {v_t1}[/{style_t1}]  [dim](conf: {score_t1})[/dim]",
        f"[bold]LLM Escalation :[/bold] {escalated}",
        f"[bold]Tier 2 Verdict :[/bold] [{style_t2}]{icon_t2} {v_t2}[/{style_t2}]  [dim](conf: {score_t2})[/dim]",
        f"[bold]Service Type   :[/bold] {llm_output['service_type']}",
        f"[bold]Auth Mechanisms:[/bold] {auth_mechs}",
        "",
        f"[bold]Reasoning      :[/bold] {llm_output['reasoning']}",
        "",
        f"[bold]Needs Hermes   :[/bold] {browser_str}",
    ]
    if needs_browser and llm_output.get("browser_escalation_reason"):
        lines.append(f"[bold]Hermes Reason  :[/bold] [italic dim]{llm_output['browser_escalation_reason']}[/italic dim]")

    panel_style = style_t2.replace("reverse", "").strip().split()[0] if style_t2 else "white"
    
    console.print(
        Panel(
            "\n".join(lines),
            title=f"[bold]Final Result (Tier 1 + Tier 2) — {domain}[/bold]",
            border_style=panel_style,
            padding=(0, 2),
        )
    )

    if llm_output.get("_error"):
        console.print(f"[red]LLM Error:[/red] {llm_output['_error']}\n")


async def run(args: argparse.Namespace) -> int:
    if args.domain:
        from utils.urls import normalise_domain
        hostname = normalise_domain(args.domain)
        domains = [Domain(hostname=hostname, probe_scheme=args.scheme)]
    else:
        from loaders.proxy_host_loader import load_domains
        domains = load_domains(args.input)

    console.rule("[bold blue]Phase 4 — Tier 2 LLM Analysis[/bold blue]")
    console.print(f"Target Local LLM endpoint: [cyan]{settings.llm_base_url}[/cyan] (Model: {settings.llm_model})\n")

    # --- Phase 2: Probe ---
    with console.status("Probing domains (Tier 1)..."):
        probe_sets = await probe_all(domains)

    all_results = []
    
    # --- Phase 4: Local LLM Client Context ---
    async with LLMClient() as vllm:
        for d, ps in zip(domains, probe_sets):
            # Tier 1
            signals = extract_signals(ps)
            rule_output = evaluate(signals, ps)
            
            # Tier 2
            with console.status(f"Analyzing {d.hostname} (Tier 2)..."):
                llm_output = await analyze_domain(d, ps, rule_output, vllm)
                
            all_results.append({
                "domain": d.hostname,
                "tier1": rule_output,
                "tier2": llm_output,
            })

    if args.json:
        print(json.dumps(all_results, indent=2, default=str))
        return 0

    for r in all_results:
        print_tier2_result(r["domain"], r["tier2"], r["tier1"])

    return 0


def main() -> int:
    args = parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
