"""
tier2/prompts.py — LLM prompt templates and response parser for Tier 2.

Provides:
  SYSTEM_PROMPT              — Static system message for the auth-detection role.
  build_analysis_prompt()    — Assembles the full message list for one domain.
  parse_llm_response()       — Extracts and validates JSON from the model output.

Expected LLM output schema
--------------------------
{
    "verdict": "PROTECTED|PARTIAL|OPEN|OPEN_API|OPEN_API_CRITICAL|
                OPEN_DOCS|GRAPHQL_OPEN|GRAPHQL_CRITICAL|UNREACHABLE|UNKNOWN",
    "confidence": <int 0-100>,
    "service_type": "WEB_APP|REST_API|GRAPHQL|MIXED|UNKNOWN",
    "auth_mechanisms_detected": ["<string>", ...],
    "reasoning": "<clear explanation>",
    "needs_browser_escalation": <true|false>,
    "browser_escalation_reason": "<string or null>"
}

Design notes
------------
- System prompt is strict JSON-only to prevent model chatter.
- User prompt is structured with labelled sections for reliable parsing.
- parse_llm_response() strips markdown fences, finds the JSON block, and
  validates required fields with safe defaults.
- The qwen3 series supports a thinking mode (``<think>...</think>``);
  parse_llm_response() strips these blocks before JSON extraction.
"""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid enumeration values for LLM output validation
# ---------------------------------------------------------------------------

_VALID_VERDICTS = frozenset(
    {
        "PROTECTED",
        "PARTIAL",
        "OPEN",
        "OPEN_API",
        "OPEN_API_CRITICAL",
        "OPEN_DOCS",
        "GRAPHQL_OPEN",
        "GRAPHQL_CRITICAL",
        "UNREACHABLE",
        "UNKNOWN",
    }
)

_VALID_SERVICE_TYPES = frozenset(
    {"WEB_APP", "REST_API", "GRAPHQL", "MIXED", "UNKNOWN"}
)

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a security analyst specialising in web authentication detection.

Your task is to analyse HTTP probe data for a domain and determine:
1. Whether the service is protected by authentication
2. What type of service it is
3. What authentication mechanisms are present
4. Whether browser-level inspection (Tier 3) is required to resolve ambiguity

OUTPUT RULES:
- Output ONLY valid JSON. No markdown code fences, no explanation, no preamble.
- Do not add any text before or after the JSON object.
- Your output must exactly match the schema below.

REQUIRED OUTPUT SCHEMA:
{
    "verdict": "<one of: PROTECTED|PARTIAL|OPEN|OPEN_API|OPEN_API_CRITICAL|OPEN_DOCS|GRAPHQL_OPEN|GRAPHQL_CRITICAL|UNREACHABLE|UNKNOWN>",
    "confidence": <integer 0-100>,
    "service_type": "<one of: WEB_APP|REST_API|GRAPHQL|MIXED|UNKNOWN>",
    "auth_mechanisms_detected": ["<auth mechanism string>", ...],
    "reasoning": "<clear, concise explanation of your verdict>",
    "needs_browser_escalation": <true|false>,
    "browser_escalation_reason": "<reason string, or null>"
}

VERDICT GUIDE:
- PROTECTED       : Evidence of authentication barrier (401, redirect to login, login form)
- PARTIAL         : Some auth evidence but inconsistent or unclear
- OPEN            : Publicly accessible HTML/web app with no auth signals
- OPEN_API        : API endpoint returns data without auth challenge
- OPEN_API_CRITICAL : API returns sensitive data (emails, tokens, PII) without auth
- OPEN_DOCS       : API documentation (Swagger/OpenAPI/ReDoc) accessible without auth
- GRAPHQL_OPEN    : GraphQL endpoint reachable without auth
- GRAPHQL_CRITICAL : GraphQL introspection available without auth
- UNREACHABLE     : Could not connect to the domain
- UNKNOWN         : Insufficient evidence to classify

CONSERVATIVE RULES:
- A page with a login *link* in nav ≠ PROTECTED (it might just be a public site with optional login)
- A single 403 on root alone ≠ PROTECTED (may be IP restriction, not credential-based auth)
- Short/empty HTML ≠ definitive answer — suspect SPA and set needs_browser_escalation=true
- If unsure between two verdicts, choose the lower-confidence option and escalate
- For service_type, trust the Tier 1 guess. Do NOT classify an SPA shell as MIXED just because its catch-all router returns HTML for /api paths.

BROWSER ESCALATION (set needs_browser_escalation=true) when:
- You are not 100% certain about the authentication status
- Root HTML body is very short or appears to be an SPA shell
- JavaScript execution is required to render login UI
- Evidence suggests modal or client-side auth (no form in HTML)
- Service type is MIXED and auth coverage is unclear
- confidence < 90

NOTE ON 403 BLOCKS (WAF / S3 / IP RESTRICTION):
- If all paths return 403 Forbidden without any login UI, and the domain appears to be an S3 bucket (e.g. s3 keywords in domain) or a pure API, classify it as PROTECTED and set service_type to REST_API. An IP restriction or bucket policy is an access control mechanism. Do not use PARTIAL for S3/API global 403s.
"""

# ---------------------------------------------------------------------------
# User message builder
# ---------------------------------------------------------------------------


def build_analysis_prompt(
    domain: str,
    rule_output: dict,
    probe_summary: dict,
    html_summary: str,
) -> list[dict[str, str]]:
    """
    Assemble the full messages list for one Tier 2 LLM call.

    Args:
        domain:       The hostname being analysed.
        rule_output:  Dict returned by ``tier1.rule_engine.evaluate()``.
        probe_summary: Dict returned by ``ProbeSet.compact_summary()``.
        html_summary: Plain-text summary from ``html_summarizer.summarize_html()``.

    Returns:
        A list of message dicts in OpenAI chat format:
        ``[{"role": "system", ...}, {"role": "user", ...}]``
    """
    user_content = _build_user_content(domain, rule_output, probe_summary, html_summary)
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def _build_user_content(
    domain: str,
    rule_output: dict,
    probe_summary: dict,
    html_summary: str,
) -> str:
    """Build the structured user message block."""
    lines: list[str] = []

    # --- Section 1: Domain ---
    lines.append(f"DOMAIN: {domain}")
    lines.append("")

    # --- Section 2: Tier 1 rule engine summary ---
    lines.append("TIER 1 RULE ENGINE RESULT:")
    lines.append(f"  Initial verdict : {rule_output.get('rule_verdict', 'UNKNOWN')}")
    lines.append(f"  Confidence score: {rule_output.get('rule_score', 0)}/100")
    lines.append(f"  Service type    : {rule_output.get('service_type_guess', 'UNKNOWN')}")
    triggered = rule_output.get("triggered_rules", [])
    if triggered:
        lines.append(f"  Triggered rules : {', '.join(triggered)}")
    ambiguity = rule_output.get("ambiguity_reason")
    if ambiguity:
        lines.append(f"  Ambiguity note  : {ambiguity}")
    lines.append("")

    # --- Section 3: Probe summary ---
    lines.append("PROBE RESULTS SUMMARY:")
    # probe_summary is a flat dict: {path: {status, final_url, content_type, ...}}
    # (as returned by ProbeSet.compact_summary())
    for path, info in probe_summary.items():
        status = info.get("status")
        ct = (info.get("content_type") or "").split(";")[0].strip()
        redirects = info.get("redirect_count", 0)
        error = info.get("error")
        if error:
            lines.append(f"  {path:30s}  ERROR: {error[:60]}")
        else:
            redirect_str = f"  → {info.get('final_url', '')}" if redirects else ""
            lines.append(f"  {path:30s}  {str(status):5s}  {ct:<30s}{redirect_str}")
    lines.append("")

    # --- Section 3b: Status distribution (always helpful, especially for non-HTML) ---
    if probe_summary:
        status_counts: dict[int, int] = {}
        ct_counts: dict[str, int] = {}
        for info in probe_summary.values():
            s = info.get("status")
            if s:
                status_counts[s] = status_counts.get(s, 0) + 1
            ct = (info.get("content_type") or "").split(";")[0].strip()
            if ct:
                ct_counts[ct] = ct_counts.get(ct, 0) + 1
        lines.append("STATUS CODE DISTRIBUTION:")
        for code, count in sorted(status_counts.items()):
            lines.append(f"  HTTP {code}: {count} path(s)")
        lines.append("CONTENT TYPE DISTRIBUTION:")
        for ct, count in sorted(ct_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {ct}: {count} path(s)")
        lines.append("")

    # --- Section 5: HTML summary ---
    if html_summary:
        lines.append("HTML CONTENT SUMMARY (root page):")
        for line in html_summary.splitlines():
            lines.append("  " + line)
        lines.append("")

    # --- Section 6: Task ---
    lines.append(
        "TASK: Based on the probe data above, determine the authentication status of this domain. "
        "Output your analysis as a single valid JSON object matching the required schema."
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------


def parse_llm_response(raw_content: str) -> dict:
    """
    Extract and validate the JSON verdict from the raw LLM output.

    Handles:
    - ``<think>...</think>`` blocks from qwen3 thinking mode
    - Markdown code fences (```json ... ```)
    - Leading/trailing prose text around the JSON block
    - Missing or invalid field values (safe defaults applied)

    Args:
        raw_content: Raw text content from the LLM choice message.

    Returns:
        A validated dict matching the Tier 2 output schema.
        On parse failure, returns an UNKNOWN verdict with
        ``needs_browser_escalation=True`` and the raw content in ``reasoning``.
    """
    if not raw_content:
        return _safe_default("Empty response from LLM.")

    # Strip qwen3 thinking blocks
    content = _strip_thinking_blocks(raw_content)

    # Strip markdown code fences
    content = _strip_code_fences(content)

    # Find the JSON block
    json_str = _extract_json_block(content)
    if not json_str:
        logger.warning("No JSON block found in LLM response. Raw: %.200s", raw_content)
        return _safe_default(f"Could not extract JSON from: {raw_content[:300]}")

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.warning("JSON parse error in LLM response: %s", exc)
        return _safe_default(f"JSON parse error: {exc}. Raw: {json_str[:200]}")

    if not isinstance(data, dict):
        return _safe_default(f"LLM returned non-dict JSON: {type(data).__name__}")

    return _validate_and_normalise(data)


def _strip_thinking_blocks(text: str) -> str:
    """Remove qwen3 <think>...</think> blocks (may span multiple lines)."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _strip_code_fences(text: str) -> str:
    """Remove markdown ``` or ```json code fences."""
    # Remove opening fence with optional language tag
    text = re.sub(r"^```(?:json)?\s*\n?", "", text.strip(), flags=re.MULTILINE)
    # Remove closing fence
    text = re.sub(r"\n?```\s*$", "", text.strip(), flags=re.MULTILINE)
    return text.strip()


def _extract_json_block(text: str) -> str | None:
    """
    Find the outermost JSON object ``{...}`` in the text.

    Handles cases where the LLM adds prose before or after the JSON.
    """
    # Quick path: if text starts with { it's probably pure JSON
    stripped = text.strip()
    if stripped.startswith("{"):
        return stripped

    # Find the first { and match its closing }
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i, ch in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    return None


def _validate_and_normalise(data: dict) -> dict:
    """Apply safe defaults and validate enum fields."""
    # verdict
    verdict = str(data.get("verdict", "UNKNOWN")).upper()
    if verdict not in _VALID_VERDICTS:
        logger.warning("LLM returned unknown verdict %r — defaulting to UNKNOWN", verdict)
        verdict = "UNKNOWN"

    # confidence
    try:
        confidence = int(data.get("confidence", 0))
        confidence = max(0, min(100, confidence))
    except (TypeError, ValueError):
        confidence = 0

    # service_type
    stype = str(data.get("service_type", "UNKNOWN")).upper()
    if stype not in _VALID_SERVICE_TYPES:
        stype = "UNKNOWN"

    # auth_mechanisms_detected
    mechanisms = data.get("auth_mechanisms_detected", [])
    if not isinstance(mechanisms, list):
        mechanisms = [str(mechanisms)] if mechanisms else []

    # reasoning
    reasoning = str(data.get("reasoning", "")).strip()

    # needs_browser_escalation
    needs_browser = bool(data.get("needs_browser_escalation", False))
    # Force escalation for anything less than near-certainty
    if confidence < 90:
        needs_browser = True

    # browser_escalation_reason
    browser_reason = data.get("browser_escalation_reason")
    if browser_reason is not None:
        browser_reason = str(browser_reason).strip() or None

    return {
        "verdict": verdict,
        "confidence": confidence,
        "service_type": stype,
        "auth_mechanisms_detected": mechanisms,
        "reasoning": reasoning,
        "needs_browser_escalation": needs_browser,
        "browser_escalation_reason": browser_reason,
    }


def _safe_default(reason: str) -> dict:
    """Return a safe UNKNOWN verdict with full escalation."""
    return {
        "verdict": "UNKNOWN",
        "confidence": 0,
        "service_type": "UNKNOWN",
        "auth_mechanisms_detected": [],
        "reasoning": reason,
        "needs_browser_escalation": True,
        "browser_escalation_reason": "LLM response parsing failed — browser inspection required.",
    }
