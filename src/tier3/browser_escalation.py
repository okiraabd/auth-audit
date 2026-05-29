"""
tier3/browser_escalation.py — Tier 3 browser escalation orchestrator.

Drives the full Tier 3 flow for a single domain that has been flagged for
browser-level inspection:

  1. Builds the appropriate Hermes task payload via ``hermes_tasks``
  2. Submits the task via ``HermesClient``
  3. Parses and validates the browser result
  4. Captures screenshot metadata and stores paths in the result
  5. Returns a structured Tier 3 result dict

Expected output schema:
{
    "verdict": str,
    "confidence": int,
    "visual_evidence": str,
    "interaction_steps": list[str],
    "reasoning": str,
    "screenshots": list[str],   # paths relative to output dir
}

Escalation is triggered ONLY for domains that remain ambiguous after Tier 2.
NEVER escalate domains that already have a high-confidence verdict.
"""

from __future__ import annotations


async def escalate(domain: str, tier2_output: dict) -> dict:
    """
    Run Tier 3 browser escalation for a single domain.

    Returns:
        A dict matching the Tier 3 output schema.
    """
    raise NotImplementedError("escalate() not yet implemented — Phase 5.")
