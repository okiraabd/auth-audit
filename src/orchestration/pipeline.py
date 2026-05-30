"""
orchestration/pipeline.py — Main pipeline orchestrator.

Ties together all tiers:
  Active Discovery: API route discovery (wordlist / kiterunner)  →  enriched ProbeSet
  Tier 1: HTTP probing  →  ProbeSet
  Tier 2: LLM analysis  →  LLM verdict
  Tier 3: Hermes browser  →  Browser verdict (only if needed)

And assembles the final DomainResult for each domain.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from config import settings
from loaders.proxy_host_loader import load_domains
from models.domain import Domain
from models.probes import ProbeSet
from models.result import DomainResult, ServiceType, Verdict
from prober.http_prober import probe_domain, _make_client
from tier1.rule_engine import evaluate
from tier1.signal_extractor import extract_signals
from tier2.llm_analyzer import analyze_domain
from tier2.llm_client import LLMClient
from tier3.hermes_client import HermesClient
from tier3.hermes_tasks import build_auth_check_task
from discovery.route_discoverer import discover_and_merge

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result assembler
# ---------------------------------------------------------------------------

def _assemble_result(
    domain: Domain,
    probe_set: ProbeSet,
    signals: list[str],
    discovery_output: dict | None,
    tier1_output: dict,
    tier2_output: dict | None,
    tier3_output: dict | None,
) -> DomainResult:
    """
    Merge outputs from all tiers into a single DomainResult.

    The final verdict priority is: Tier 3 > Tier 2 > Tier 1.
    Confidence and reasoning are taken from the highest tier that ran.
    """
    tier_reached = 1

    # Start from Tier 1
    final_verdict = Verdict(tier1_output.get("rule_verdict", "UNKNOWN"))
    confidence = tier1_output.get("rule_score", 0)
    reasoning = tier1_output.get("ambiguity_reason") or f"Tier 1 rule engine verdict: {final_verdict.value}"
    service_type = ServiceType(tier1_output.get("service_type_guess", "UNKNOWN"))

    # Override with Tier 2 if available
    if tier2_output:
        tier_reached = 2
        t2_verdict = tier2_output.get("verdict", "UNKNOWN")
        if t2_verdict and t2_verdict != "UNKNOWN":
            final_verdict = Verdict(t2_verdict)
        if tier2_output.get("confidence", 0) > confidence:
            confidence = tier2_output["confidence"]
        if tier2_output.get("reasoning"):
            reasoning = tier2_output["reasoning"]
        t2_service = tier2_output.get("service_type")
        if t2_service and t2_service != "UNKNOWN":
            service_type = ServiceType(t2_service)

    # Override with Tier 3 if available (highest authority)
    if tier3_output and not tier3_output.get("_error"):
        tier_reached = 3
        t3_verdict = tier3_output.get("verdict", "UNKNOWN")
        if t3_verdict and t3_verdict != "UNKNOWN":
            final_verdict = Verdict(t3_verdict)
        if tier3_output.get("confidence", 0) > 0:
            confidence = tier3_output["confidence"]
        if tier3_output.get("reasoning"):
            reasoning = tier3_output["reasoning"]

    # Build evidence list
    evidence: list[str] = []
    if tier3_output:
        ev = tier3_output.get("visual_evidence")
        if ev:
            evidence.append(f"Browser: {ev}")
        for ss in tier3_output.get("screenshots", []):
            if ss:
                evidence.append(f"Screenshot: {ss}")
        for step in tier3_output.get("interaction_steps", []):
            evidence.append(f"Step: {step}")

    return DomainResult(
        domain=domain.hostname,
        service_type=service_type,
        final_verdict=final_verdict,
        confidence=confidence,
        tier_reached=tier_reached,
        signals=signals,
        reasoning=reasoning,
        evidence=evidence,
        probe_summary=probe_set.compact_summary() if hasattr(probe_set, "compact_summary") else {},
        discovery_output=discovery_output,
        tier1_output=tier1_output,
        tier2_output=tier2_output,
        tier3_output=tier3_output,
    )


# ---------------------------------------------------------------------------
# Hermes escalation guard
# ---------------------------------------------------------------------------

def _should_skip_hermes(probe_set: ProbeSet, tier1_output: dict) -> bool:
    """
    Return True when Hermes would be a wasted call:
      - All probes are plain 404s (misconfigured / no routes)
      - Domain is fully unreachable (all network errors)
      - Tier 1 ambiguity reason explicitly says 'no matching routes'
    """
    if probe_set.all_unreachable:
        return True

    successful = probe_set.successful_probes()
    if successful and len(successful) >= 5:
        # All-404 with text/plain — backend routing error, no UI to render
        if all(
            p.status_code == 404 and (p.content_type or "").startswith("text/plain")
            for p in successful
        ):
            return True

    reason = (tier1_output.get("ambiguity_reason") or "").lower()
    if "no matching routes" in reason:
        return True

    return False


# ---------------------------------------------------------------------------
# Per-domain pipeline
# ---------------------------------------------------------------------------

async def _process_domain(
    domain: Domain,
    probe_set: ProbeSet,
    llm_client: LLMClient,
    hermes_client: HermesClient,
    llm_semaphore: asyncio.Semaphore,
    hermes_semaphore: asyncio.Semaphore,
) -> DomainResult:
    """Run Active Discovery → Tier 1 → Tier 2 → (optional) Tier 3 for a single domain."""

    # Active Discovery — API route discovery (only fires if most initial probes are 404)
    probe_set, discovery_output = await discover_and_merge(domain, probe_set)

    # Tier 1 — rule engine
    signals = extract_signals(probe_set)
    tier1_output = evaluate(signals, probe_set)
    logger.debug("[T1] %s → %s (conf:%d, llm:%s)",
                 domain.hostname,
                 tier1_output["rule_verdict"],
                 tier1_output["rule_score"],
                 tier1_output["needs_llm"])

    # Tier 2 — LLM analysis (if needed)
    tier2_output: dict | None = None
    if tier1_output.get("needs_llm", False) or tier1_output["rule_score"] < settings.tier2_escalation_threshold:
        async with llm_semaphore:
            tier2_output = await analyze_domain(domain, probe_set, tier1_output, llm_client)
        logger.debug("[T2] %s → %s (conf:%d, hermes:%s)",
                     domain.hostname,
                     tier2_output.get("verdict"),
                     tier2_output.get("confidence", 0),
                     tier2_output.get("needs_browser_escalation"))

    # Tier 3 — Hermes browser (only if Tier 2 says so AND the service is viable)
    tier3_output: dict | None = None
    escalation_reason = (tier2_output or {}).get("browser_escalation_reason") or ""
    if tier2_output and tier2_output.get("needs_browser_escalation"):
        if _should_skip_hermes(probe_set, tier1_output):
            logger.info(
                "[T3] Skipping Hermes for %s — service is broken/unreachable (no viable content)",
                domain.hostname,
            )
        else:
            async with hermes_semaphore:
                logger.info("[T3] Escalating %s to Hermes: %s", domain.hostname, escalation_reason[:80])
                task_payload = build_auth_check_task(
                    domain=domain.hostname,
                    escalation_reason=escalation_reason,
                    tier2_output=tier2_output,
                )
                tier3_output = await hermes_client.submit_task(task_payload)
                logger.debug("[T3] %s → %s (conf:%d)",
                             domain.hostname,
                             tier3_output.get("verdict"),
                             tier3_output.get("confidence", 0))

    return _assemble_result(domain, probe_set, signals, discovery_output, tier1_output, tier2_output, tier3_output)

async def _process_domain_full(
    domain: Domain,
    http_client,
    llm_client: LLMClient,
    hermes_client: HermesClient,
    llm_semaphore: asyncio.Semaphore,
    hermes_semaphore: asyncio.Semaphore,
) -> DomainResult:
    """End-to-End processing: Tier 1 probing followed by analysis."""
    try:
        probe_set = await probe_domain(domain, http_client)
        return await _process_domain(domain, probe_set, llm_client, hermes_client, llm_semaphore, hermes_semaphore)
    except Exception as exc:
        logger.error("CRITICAL: Pipeline crash processing %s: %s", domain.hostname, exc, exc_info=True)
        return DomainResult(
            domain=domain.hostname,
            service_type=ServiceType.UNKNOWN,
            final_verdict=Verdict.UNKNOWN,
            confidence=0,
            tier_reached=0,
            signals=[],
            reasoning=f"Pipeline crashed during execution: {exc}",
            evidence=[],
            probe_summary={},
        )


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------

async def run_pipeline(input_file: str | None = None) -> list[DomainResult]:
    """
    Run the full 3-tier auth-detection pipeline with JSONL checkpointing.
    """
    started_at = datetime.now(timezone.utc)
    source = input_file or str(settings.proxy_hosts_file)

    logger.info("═══════════════════════════════════════════════")
    logger.info(" auth-audit pipeline starting (E2E Checkpointing)")
    logger.info(" Input: %s", source)
    logger.info(" Local LLM:  %s  (model: %s)", settings.llm_base_url, settings.llm_model)
    logger.info(" Hermes: %s", settings.hermes_base_url)
    logger.info("═══════════════════════════════════════════════")

    # 1. Load checkpoint
    completed_domains: set[str] = set()
    results: list[DomainResult] = []
    jsonl_path = settings.results_jsonl

    if jsonl_path.exists():
        logger.info("Found existing checkpoint: %s", jsonl_path)
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    dr = DomainResult(**data)
                    completed_domains.add(dr.domain)
                    results.append(dr)
                except Exception as e:
                    logger.warning("Failed to parse JSONL line: %s", e)
        logger.info("Loaded %d completed domains from checkpoint.", len(completed_domains))

    # 2. Load and filter domains
    all_domains = load_domains(source)
    pending_domains = [d for d in all_domains if d.hostname not in completed_domains]
    
    logger.info("Loaded %d domain(s) total. %d pending.", len(all_domains), len(pending_domains))

    if not pending_domains:
        logger.info("All domains already processed.")
        return results

    # 3. Process pending domains
    logger.info("▶ Processing %d pending domain(s) End-to-End...", len(pending_domains))
    hermes_semaphore = asyncio.Semaphore(settings.hermes_concurrency)
    llm_semaphore = asyncio.Semaphore(settings.llm_concurrency)
    http_semaphore = asyncio.Semaphore(settings.prober_concurrency)
    s3_upload_lock = asyncio.Lock()

    async with _make_client() as http_client, LLMClient() as llm_client, HermesClient() as hermes_client:
        
        async def bounded_process(domain: Domain) -> DomainResult:
            async with http_semaphore:
                res = await _process_domain_full(domain, http_client, llm_client, hermes_client, llm_semaphore, hermes_semaphore)
                # Atomic append to JSONL
                with open(jsonl_path, "a", encoding="utf-8") as f:
                    f.write(res.model_dump_json() + "\n")
                return res

        async def _upload_checkpoint(path: Path, force: bool = False) -> None:
            if not force and s3_upload_lock.locked():
                return
            async with s3_upload_lock:
                try:
                    import boto3
                    from botocore.config import Config
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=settings.s3_endpoint,
                        aws_access_key_id=settings.s3_access_key,
                        aws_secret_access_key=settings.s3_secret_key,
                        region_name="us-east-1",
                        config=Config(connect_timeout=5, read_timeout=15)
                    )
                    report_key = f"{settings.s3_report_prefix.rstrip('/')}/latest_checkpoint.jsonl"
                    
                    def _do_upload():
                        s3_client.upload_file(str(path), settings.s3_bucket, report_key)
                    
                    await asyncio.to_thread(_do_upload)
                    logger.debug("[S3] Checkpoint uploaded to %s", report_key)
                except Exception as e:
                    logger.warning("[S3] Failed to upload checkpoint: %s", e)

        tasks = [asyncio.create_task(bounded_process(d)) for d in pending_domains]
        
        count = 0
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            count += 1
            # Periodic sync every 50 domains
            if count % 50 == 0 and settings.s3_enabled:
                asyncio.create_task(_upload_checkpoint(jsonl_path))

        # Final sync for any remaining domains
        if settings.s3_enabled and count > 0:
            logger.info("Executing final S3 checkpoint sync...")
            await _upload_checkpoint(jsonl_path, force=True)

    elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
    logger.info("═══════════════════════════════════════════════")
    logger.info(" Pipeline complete: %d results in %.1fs", len(results), elapsed)
    logger.info("═══════════════════════════════════════════════")

    return results
