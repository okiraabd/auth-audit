"""
tier1/rule_engine.py — Deterministic, explainable Tier 1 rule engine.

Consumes extracted signals (from ``tier1.signal_extractor``) and a
``ProbeSet`` and applies weighted, named rules to produce a structured verdict.

Design philosophy
-----------------
- Rules are applied in **priority order** — the first confident match wins.
- If no rule is confident, the engine falls through to PARTIAL / UNKNOWN
  and sets ``needs_llm=True`` to trigger Tier 2 escalation.
- The engine should **prefer escalation over a wrong verdict**.
- Rule scoring is additive; the final score is normalised to 0–100.

Output schema (returned dict)
-----------------------------
{
    "service_type_guess": "WEB_APP | REST_API | GRAPHQL | MIXED | UNKNOWN",
    "rule_score": int,              # 0–100 confidence in the verdict
    "rule_verdict": str,            # Verdict label (see models.result.Verdict)
    "triggered_rules": list[str],   # Signal labels that drove the verdict
    "needs_llm": bool,              # True → escalate to Tier 2
    "ambiguity_reason": str | None, # Human-readable reason for escalation
}
"""

from __future__ import annotations

import logging

from models.probes import ProbeSet
from models.result import ServiceType, Verdict
from tier1.signal_extractor import (
    R_401_BASIC,
    R_401_BEARER,
    R_401_DIGEST,
    R_403_FORBIDDEN,
    R_AUTH_REDIRECT_EXTERNAL,
    R_AUTH_REDIRECT_PATH,
    R_AUTH_REDIRECT_PROVIDER,
    R_CORS_HEADERS,
    R_GRAPHQL_INTROSPECTION,
    R_GRAPHQL_OPEN,
    R_GRAPHQL_RESPONSE,
    R_HTML_RESPONSE,
    R_JSON_BODY,
    R_JSON_CONTENT_TYPE,
    R_LOGIN_FORM,
    R_LOGIN_KEYWORD,
    R_OPEN_API_DATA,
    R_OPEN_DOCS,
    R_OPENAPI_MARKER,
    R_PASSWORD_FIELD,
    R_RATE_LIMIT_HEADERS,
    R_REDOC_MARKER,
    R_SENSITIVE_FIELDS,
    R_SESSION_COOKIE,
    R_SPA_SHELL,
    R_SWAGGER_MARKER,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimum rule_score below which needs_llm is forced True
# ---------------------------------------------------------------------------
_LLM_ESCALATION_SCORE_THRESHOLD = 65


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate(signals: list[str], probe_set: ProbeSet) -> dict:
    """
    Apply all rules to the extracted signals and return a rule engine result.

    Args:
        signals:   Sorted list of signal label strings from ``extract_signals``.
        probe_set: The raw ``ProbeSet`` for cross-probe information.

    Returns:
        A dict matching the rule engine output schema (see module docstring).
    """
    sig = frozenset(signals)

    # ------------------------------------------------------------------
    # 1. Network / Service Layer Validation (Dead or Unreachable)
    # ------------------------------------------------------------------
    if probe_set.all_unreachable:
        return _result(
            verdict=Verdict.UNREACHABLE,
            service_type=ServiceType.UNKNOWN,
            score=95,
            triggered=[],
            needs_llm=False,
            reason=None,
        )
        
    successful = probe_set.successful_probes()
    if successful:
        # If every response is a 502/503/504 (dead backend), treat as UNREACHABLE
        if all(p.status_code in {502, 503, 504} for p in successful):
            return _result(
                verdict=Verdict.UNREACHABLE,
                service_type=ServiceType.UNKNOWN,
                score=95,
                triggered=[],
                needs_llm=False,
                reason="All paths returned 502/503/504 indicating the backend service is dead.",
            )
    # ------------------------------------------------------------------
    # 1b. Uniform 403 across nearly all paths → blocked/IP-restricted
    # ------------------------------------------------------------------
    if successful:
        forbidden_count = sum(1 for p in successful if p.status_code == 403)
        forbidden_ratio = forbidden_count / len(successful)
        if forbidden_ratio >= 0.75 and len(successful) >= 5:
            # 403 everywhere = access control enforced (WAF, IP restriction, or credential gate)
            return _result(
                verdict=Verdict.PROTECTED,
                service_type=ServiceType.UNKNOWN,
                score=75,
                triggered=[R_403_FORBIDDEN],
                needs_llm=True,
                reason=(
                    f"{forbidden_count}/{len(successful)} paths return HTTP 403 Forbidden — "
                    "strong access control enforced (WAF, IP restriction, or auth gate). "
                    "LLM may clarify whether this is credential-based auth."
                ),
            )

    # ------------------------------------------------------------------
    # 1c. Uniform 404 / plain-text across all paths → broken service
    # ------------------------------------------------------------------
    if successful:
        ok_404_plain = all(
            p.status_code == 404 and (p.content_type or "").startswith("text/plain")
            for p in successful
        )
        if ok_404_plain and len(successful) >= 5:
            return _result(
                verdict=Verdict.UNKNOWN,
                service_type=ServiceType.UNKNOWN,
                score=20,
                triggered=[],
                needs_llm=True,
                reason=(
                    "All probed paths return HTTP 404 with text/plain body — "
                    "service appears misconfigured or has no matching routes. "
                    "Cannot determine authentication status."
                ),
            )

    # ------------------------------------------------------------------
    # 2. Strong auth signals → PROTECTED (high confidence)
    # ------------------------------------------------------------------

    # 2a. HTTP 401 with explicit WWW-Authenticate scheme — very strong
    if R_401_BASIC in sig:
        return _result(
            verdict=Verdict.PROTECTED,
            service_type=_classify_service(sig),
            score=93,
            triggered=[R_401_BASIC],
            needs_llm=False,
            reason=None,
        )

    if R_401_DIGEST in sig:
        return _result(
            verdict=Verdict.PROTECTED,
            service_type=_classify_service(sig),
            score=92,
            triggered=[R_401_DIGEST],
            needs_llm=False,
            reason=None,
        )

    if R_401_BEARER in sig:
        return _result(
            verdict=Verdict.PROTECTED,
            service_type=_classify_service(sig),
            score=92,
            triggered=[R_401_BEARER],
            needs_llm=False,
            reason=None,
        )

    # 2b. Redirect to known auth provider — very strong
    if R_AUTH_REDIRECT_PROVIDER in sig:
        return _result(
            verdict=Verdict.PROTECTED,
            service_type=_classify_service(sig),
            score=88,
            triggered=[R_AUTH_REDIRECT_PROVIDER],
            needs_llm=False,
            reason=None,
        )

    # ------------------------------------------------------------------
    # 3. Severe open exposure signals → critical verdicts
    # ------------------------------------------------------------------

    # 3a. GraphQL introspection fully open
    if R_GRAPHQL_INTROSPECTION in sig:
        return _result(
            verdict=Verdict.GRAPHQL_CRITICAL,
            service_type=ServiceType.GRAPHQL,
            score=90,
            triggered=[R_GRAPHQL_INTROSPECTION],
            needs_llm=False,
            reason=None,
        )

    # 3b. Open API returning sensitive data
    if R_OPEN_API_DATA in sig and R_SENSITIVE_FIELDS in sig:
        return _result(
            verdict=Verdict.OPEN_API_CRITICAL,
            service_type=ServiceType.REST_API,
            score=88,
            triggered=[R_OPEN_API_DATA, R_SENSITIVE_FIELDS],
            needs_llm=False,
            reason=None,
        )

    # 3c. Open API docs exposed (Swagger/OpenAPI/ReDoc accessible)
    if R_OPEN_DOCS in sig and _no_auth_signals(sig):
        has_marker = R_SWAGGER_MARKER in sig or R_OPENAPI_MARKER in sig or R_REDOC_MARKER in sig
        if has_marker:
            doc_triggers = [s for s in [R_OPEN_DOCS, R_SWAGGER_MARKER, R_OPENAPI_MARKER, R_REDOC_MARKER] if s in sig]
            return _result(
                verdict=Verdict.OPEN_DOCS,
                service_type=ServiceType.REST_API,
                score=82,
                triggered=doc_triggers,
                needs_llm=False,
                reason=None,
            )

    # ------------------------------------------------------------------
    # 4. Moderate auth signals → PROTECTED with lower confidence
    # ------------------------------------------------------------------

    # Auth redirect to path + no open-API counter-signal
    if R_AUTH_REDIRECT_PATH in sig and R_OPEN_API_DATA not in sig:
        # If also external redirect, even stronger
        score = 82 if R_AUTH_REDIRECT_EXTERNAL in sig else 72
        triggered = [s for s in [R_AUTH_REDIRECT_PATH, R_AUTH_REDIRECT_EXTERNAL] if s in sig]
        # But if we also see JSON data — mixed — escalate
        if R_JSON_BODY in sig or R_JSON_CONTENT_TYPE in sig:
            return _result(
                verdict=Verdict.PARTIAL,
                service_type=ServiceType.MIXED,
                score=55,
                triggered=triggered + [R_JSON_BODY],
                needs_llm=True,
                reason=(
                    "Root page redirects to auth path but some paths return JSON data — "
                    "possibly mixed web/API service with partial protection."
                ),
            )
        return _result(
            verdict=Verdict.PROTECTED,
            service_type=_classify_service(sig),
            score=score,
            triggered=triggered,
            needs_llm=score < _LLM_ESCALATION_SCORE_THRESHOLD,
            reason="Auth redirect detected but confidence below threshold." if score < _LLM_ESCALATION_SCORE_THRESHOLD else None,
        )

    # Login form with password field — HTML web app with clear auth UI
    if R_PASSWORD_FIELD in sig and R_LOGIN_FORM in sig:
        return _result(
            verdict=Verdict.PROTECTED,
            service_type=ServiceType.WEB_APP,
            score=78,
            triggered=[R_PASSWORD_FIELD, R_LOGIN_FORM],
            needs_llm=False,
            reason=None,
        )

    # Only password field (no form action detected) — lower confidence
    if R_PASSWORD_FIELD in sig:
        return _result(
            verdict=Verdict.PROTECTED,
            service_type=ServiceType.WEB_APP,
            score=62,
            triggered=[R_PASSWORD_FIELD],
            needs_llm=True,
            reason="Password field detected in HTML but no form action confirmed — may need browser inspection.",
        )

    # ------------------------------------------------------------------
    # 5. Open API without sensitive data
    # ------------------------------------------------------------------
    if R_OPEN_API_DATA in sig and R_SENSITIVE_FIELDS not in sig:
        return _result(
            verdict=Verdict.OPEN_API,
            service_type=ServiceType.REST_API,
            score=72,
            triggered=[R_OPEN_API_DATA],
            needs_llm=True,
            reason="API path returns JSON data without auth challenge — content sensitivity unclear.",
        )

    # ------------------------------------------------------------------
    # 6. GraphQL open but no confirmed introspection
    # ------------------------------------------------------------------
    if R_GRAPHQL_OPEN in sig and R_GRAPHQL_INTROSPECTION not in sig:
        if _no_auth_signals(sig):
            # If it's pure HTML with no JSON anywhere, it's likely a catch-all SPA router, not GraphQL.
            if R_HTML_RESPONSE in sig and R_JSON_BODY not in sig and R_JSON_CONTENT_TYPE not in sig:
                pass  # Fall through to WEB_APP rules
            else:
                return _result(
                    verdict=Verdict.GRAPHQL_OPEN,
                    service_type=ServiceType.GRAPHQL,
                    score=60,
                    triggered=[R_GRAPHQL_OPEN],
                    needs_llm=True,
                    reason="GraphQL path reachable without auth — introspection status unknown; browser inspection may clarify.",
                )

    # ------------------------------------------------------------------
    # 7. Weak / indirect auth signals → PARTIAL, escalate
    # ------------------------------------------------------------------
    weak_auth = [s for s in [R_403_FORBIDDEN, R_LOGIN_KEYWORD, R_SESSION_COOKIE] if s in sig]
    if weak_auth:
        return _result(
            verdict=Verdict.PARTIAL,
            service_type=_classify_service(sig),
            score=45,
            triggered=weak_auth,
            needs_llm=True,
            reason=f"Weak auth indicators ({', '.join(weak_auth)}) but no definitive challenge — ambiguous.",
        )

    # SPA shell on root — cannot determine auth from HTTP alone
    if R_SPA_SHELL in sig:
        return _result(
            verdict=Verdict.UNKNOWN,
            service_type=ServiceType.WEB_APP,
            score=20,
            triggered=[R_SPA_SHELL],
            needs_llm=True,
            reason="Root page appears to be an SPA shell — JavaScript execution required to detect auth.",
        )

    # ------------------------------------------------------------------
    # 8. No auth signals, clear HTML or JSON → OPEN
    # ------------------------------------------------------------------
    if R_HTML_RESPONSE in sig and _no_auth_signals(sig):
        score = 55
        return _result(
            verdict=Verdict.OPEN,
            service_type=ServiceType.WEB_APP,
            score=score,
            triggered=[R_HTML_RESPONSE],
            needs_llm=True,
            reason="HTML page with no auth signals detected — could be public or JS-rendered auth wall.",
        )

    if (R_JSON_BODY in sig or R_JSON_CONTENT_TYPE in sig) and _no_auth_signals(sig):
        return _result(
            verdict=Verdict.OPEN_API,
            service_type=ServiceType.REST_API,
            score=55,
            triggered=[s for s in [R_JSON_BODY, R_JSON_CONTENT_TYPE] if s in sig],
            needs_llm=True,
            reason="API endpoint responds with JSON but no auth challenge detected.",
        )

    # ------------------------------------------------------------------
    # 9. Fallback — insufficient signal to classify
    # ------------------------------------------------------------------
    return _result(
        verdict=Verdict.UNKNOWN,
        service_type=ServiceType.UNKNOWN,
        score=15,
        triggered=list(sig),
        needs_llm=True,
        reason="Insufficient or contradictory signals — LLM analysis required.",
    )


# ---------------------------------------------------------------------------
# Service type classification
# ---------------------------------------------------------------------------


def _classify_service(signals: frozenset[str]) -> ServiceType:
    """
    Infer the most likely service type from the signal set.

    Called by the verdict rules to populate ``service_type_guess``.
    """
    has_graphql = R_GRAPHQL_OPEN in signals or R_GRAPHQL_RESPONSE in signals or R_GRAPHQL_INTROSPECTION in signals
    has_json = R_JSON_BODY in signals or R_JSON_CONTENT_TYPE in signals
    has_html = R_HTML_RESPONSE in signals
    has_docs = R_SWAGGER_MARKER in signals or R_OPENAPI_MARKER in signals

    if has_graphql:
        if has_html and has_json:
            return ServiceType.MIXED
        if has_html and R_GRAPHQL_RESPONSE not in signals and R_GRAPHQL_INTROSPECTION not in signals:
            # SPA catch-all router returning 200 OK HTML on /graphql
            return ServiceType.WEB_APP
        return ServiceType.GRAPHQL

    if has_docs:
        return ServiceType.REST_API
    if has_json and has_html:
        return ServiceType.MIXED
    if has_json:
        return ServiceType.REST_API
    if has_html:
        return ServiceType.WEB_APP

    # API-indicator headers suggest REST_API even without confirmed JSON
    if R_RATE_LIMIT_HEADERS in signals or R_CORS_HEADERS in signals:
        return ServiceType.REST_API

    return ServiceType.UNKNOWN


def _no_auth_signals(signals: frozenset[str]) -> bool:
    """Return True when none of the known auth signal labels are present."""
    auth_set = {
        R_401_BASIC, R_401_BEARER, R_401_DIGEST,
        R_AUTH_REDIRECT_PATH, R_AUTH_REDIRECT_EXTERNAL, R_AUTH_REDIRECT_PROVIDER,
        R_PASSWORD_FIELD, R_LOGIN_FORM, R_LOGIN_KEYWORD, R_SESSION_COOKIE,
        R_403_FORBIDDEN,
    }
    return auth_set.isdisjoint(signals)


# ---------------------------------------------------------------------------
# Output builder
# ---------------------------------------------------------------------------


def _result(
    verdict: Verdict,
    service_type: ServiceType,
    score: int,
    triggered: list[str],
    needs_llm: bool,
    reason: str | None,
) -> dict:
    """Construct the standardised rule engine output dict."""
    clamped_score = max(0, min(100, score))
    # Force LLM escalation if score is below threshold, regardless of rule decision
    force_llm = clamped_score < _LLM_ESCALATION_SCORE_THRESHOLD
    final_needs_llm = needs_llm or force_llm

    return {
        "service_type_guess": service_type.value,
        "rule_score": clamped_score,
        "rule_verdict": verdict.value,
        "triggered_rules": sorted(set(triggered)),
        "needs_llm": final_needs_llm,
        "ambiguity_reason": reason,
    }
