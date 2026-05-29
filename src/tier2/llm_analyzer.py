"""
tier2/llm_analyzer.py — Tier 2 LLM analysis orchestrator.

Takes the results of Tier 1 (ProbeSet, Rule Engine Verdict) and escalates
to the Local LLM endpoint if `needs_llm` is True.

Uses `html_summarizer` to condense the largest HTML body found in the probes,
assembles the prompt via `prompts`, and returns the parsed LLM verdict.
"""

from __future__ import annotations

import logging

from models.domain import Domain
from models.probes import ProbeSet
from tier2.html_summarizer import summarize_html
from tier2.prompts import build_analysis_prompt, parse_llm_response
from tier2.llm_client import LLMAPIError, LLMClient, LLMParseError, LLMTimeoutError

logger = logging.getLogger(__name__)


async def analyze_domain(
    domain: Domain,
    probe_set: ProbeSet,
    rule_output: dict,
    llm_client: LLMClient,
) -> dict:
    """
    Run Tier 2 LLM analysis for a single domain.

    If Tier 1 determined `needs_llm=False`, this function returns immediately
    with a mock LLM output that passes through the Tier 1 verdict.

    Args:
        domain:       The domain being analyzed.
        probe_set:    The full HTTP probe results from Tier 1.
        rule_output:  The structured verdict dict from `tier1.rule_engine.evaluate()`.
        llm_client:  A configured and shared `LLMClient` instance.

    Returns:
        A dict matching the required LLM output schema (see `prompts.py`),
        augmented with `_raw_response` and `_error` fields if applicable.
    """
    if not rule_output.get("needs_llm", True):
        logger.debug("Skipping Tier 2 for %s (Tier 1 confidence is high)", domain.hostname)
        return _passthrough_verdict(rule_output)

    logger.info("Escalating %s to Tier 2 LLM...", domain.hostname)

    # 1. Summarize the best HTML payload (usually the root path, or the largest)
    html_summary = _get_best_html_summary(probe_set)

    # 2. Build the prompt
    messages = build_analysis_prompt(
        domain=domain.hostname,
        rule_output=rule_output,
        probe_summary=probe_set.compact_summary(),
        html_summary=html_summary,
    )

    # 3. Call Local LLM
    try:
        raw_response = await llm_client.chat_completion(messages)
        # Extract content from OpenAI chat shape
        choice_msg = raw_response.get("choices", [{}])[0].get("message", {})
        content = choice_msg.get("content", "")
    except (LLMAPIError, LLMParseError, LLMTimeoutError) as exc:
        logger.warning("Tier 2 LLM call failed for %s: %s", domain.hostname, exc)
        return _fallback_verdict(rule_output, str(exc))
    except Exception as exc:
        logger.error("Unexpected error in Tier 2 for %s: %s", domain.hostname, exc, exc_info=True)
        return _fallback_verdict(rule_output, f"Unexpected error: {exc}")

    # 4. Parse the response
    parsed = parse_llm_response(content)

    # Attach debugging info
    parsed["_raw_response"] = content
    return parsed


def _passthrough_verdict(rule_output: dict) -> dict:
    """Return a Tier 2 dict that just echoes the confident Tier 1 result."""
    return {
        "verdict": rule_output.get("rule_verdict", "UNKNOWN"),
        "confidence": rule_output.get("rule_score", 100),
        "service_type": rule_output.get("service_type_guess", "UNKNOWN"),
        "auth_mechanisms_detected": [],
        "reasoning": "Tier 1 confidence was high; bypassed LLM analysis.",
        "needs_browser_escalation": False,
        "browser_escalation_reason": None,
        "_raw_response": None,
    }


def _fallback_verdict(rule_output: dict, error_msg: str) -> dict:
    """Return a safe UNKNOWN verdict when the LLM call fails."""
    return {
        "verdict": "UNKNOWN",
        "confidence": 0,
        "service_type": rule_output.get("service_type_guess", "UNKNOWN"),
        "auth_mechanisms_detected": [],
        "reasoning": f"LLM analysis failed: {error_msg}. Falling back to Tier 1 service type.",
        "needs_browser_escalation": True,
        "browser_escalation_reason": "Tier 2 failed. Requires browser inspection to determine auth status.",
        "_raw_response": None,
        "_error": error_msg,
    }


def _get_best_html_summary(probe_set: ProbeSet) -> str:
    """Find the most useful HTML payload in the probes and summarize it."""
    # Priority 1: The root path (/)
    root_probe = next((p for p in probe_set.probes if p.path == "/"), None)
    if root_probe and root_probe.is_html_response and root_probe.body_preview:
        return summarize_html(root_probe.body_preview)

    # Priority 2: Any auth path (e.g. /login)
    from utils.urls import is_auth_path
    auth_probe = next((p for p in probe_set.probes if is_auth_path(p.path) and p.is_html_response and p.body_preview), None)
    if auth_probe:
        return summarize_html(auth_probe.body_preview)

    # Priority 3: The largest HTML response
    html_probes = [p for p in probe_set.probes if p.is_html_response and p.body_preview]
    if html_probes:
        # Sort by response size descending
        html_probes.sort(key=lambda p: p.response_size_bytes or len(p.body_preview), reverse=True)
        return summarize_html(html_probes[0].body_preview)

    return ""
