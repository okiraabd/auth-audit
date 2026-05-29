"""
tier1/signal_extractor.py — Raw signal extraction from HTTP probe results.

Analyses a ``ProbeSet`` and extracts a labelled, deduplicated set of signals
that the rule engine can reason over deterministically.

Signal label conventions
------------------------
All signal labels use the ``R_`` prefix (Rule signal) for traceability.

Auth signals:
  R_401_BASIC          — 401 + WWW-Authenticate: Basic
  R_401_DIGEST         — 401 + WWW-Authenticate: Digest
  R_401_BEARER         — 401 + WWW-Authenticate: Bearer
  R_403_FORBIDDEN      — HTTP 403 on a probed path
  R_AUTH_REDIRECT_PATH — Redirect chain contains a known auth path
  R_AUTH_REDIRECT_EXTERNAL — Redirect crossed to a different domain
  R_AUTH_REDIRECT_PROVIDER — Redirect to a known auth provider (Authelia, etc.)
  R_PASSWORD_FIELD     — <input type="password"> detected in HTML
  R_LOGIN_FORM         — <form> with login-like action detected
  R_LOGIN_KEYWORD      — Login/sign-in keywords in page body
  R_SESSION_COOKIE     — Session or auth cookie in Set-Cookie header

Service-type signals:
  R_JSON_CONTENT_TYPE  — Content-Type: application/json
  R_JSON_BODY          — Body starts with { or [ (JSON object / array)
  R_HTML_RESPONSE      — Content-Type: text/html + <html> tag
  R_GRAPHQL_RESPONSE   — JSON body with 'data' or 'errors' keys (GQL style)
  R_GRAPHQL_INTROSPECTION — Introspection POST returned __schema data
  R_SWAGGER_MARKER     — Swagger UI markers in HTML or JSON
  R_OPENAPI_MARKER     — OpenAPI spec marker (openapi/swagger version field)
  R_REDOC_MARKER       — ReDoc UI markers in HTML

Risk signals:
  R_OPEN_DOCS          — API doc path responded 200 without any auth signal
  R_OPEN_API_DATA      — API path returned JSON data without auth challenge
  R_SENSITIVE_FIELDS   — Sensitive field names found in a JSON response body
  R_GRAPHQL_OPEN       — GraphQL path responded 200 (potentially open)
  R_SPA_SHELL          — Root HTML body is very small / looks like SPA shell

Other signals:
  R_RATE_LIMIT_HEADERS — X-RateLimit-* headers detected (API indicator)
  R_CORS_HEADERS       — Access-Control-Allow-* headers detected

All functions take a ``ProbeSet`` and return a frozenset of signal strings.
This module must not make any network calls or have side effects.
"""

from __future__ import annotations

import json
import logging
import re

from models.probes import ProbeResult, ProbeSet
from utils.urls import classify_redirect_chain, is_auth_path, is_known_auth_provider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal label constants — import these in rule_engine and tests
# ---------------------------------------------------------------------------

R_401_BASIC = "R_401_BASIC"
R_401_DIGEST = "R_401_DIGEST"
R_401_BEARER = "R_401_BEARER"
R_403_FORBIDDEN = "R_403_FORBIDDEN"
R_AUTH_REDIRECT_PATH = "R_AUTH_REDIRECT_PATH"
R_AUTH_REDIRECT_EXTERNAL = "R_AUTH_REDIRECT_EXTERNAL"
R_AUTH_REDIRECT_PROVIDER = "R_AUTH_REDIRECT_PROVIDER"
R_PASSWORD_FIELD = "R_PASSWORD_FIELD"
R_LOGIN_FORM = "R_LOGIN_FORM"
R_LOGIN_KEYWORD = "R_LOGIN_KEYWORD"
R_SESSION_COOKIE = "R_SESSION_COOKIE"

R_JSON_CONTENT_TYPE = "R_JSON_CONTENT_TYPE"
R_JSON_BODY = "R_JSON_BODY"
R_HTML_RESPONSE = "R_HTML_RESPONSE"
R_GRAPHQL_RESPONSE = "R_GRAPHQL_RESPONSE"
R_GRAPHQL_INTROSPECTION = "R_GRAPHQL_INTROSPECTION"
R_SWAGGER_MARKER = "R_SWAGGER_MARKER"
R_OPENAPI_MARKER = "R_OPENAPI_MARKER"
R_REDOC_MARKER = "R_REDOC_MARKER"

R_OPEN_DOCS = "R_OPEN_DOCS"
R_OPEN_API_DATA = "R_OPEN_API_DATA"
R_SENSITIVE_FIELDS = "R_SENSITIVE_FIELDS"
R_GRAPHQL_OPEN = "R_GRAPHQL_OPEN"
R_SPA_SHELL = "R_SPA_SHELL"
R_RATE_LIMIT_HEADERS = "R_RATE_LIMIT_HEADERS"
R_CORS_HEADERS = "R_CORS_HEADERS"

# ---------------------------------------------------------------------------
# Sensitive field names that indicate real data exposure
# ---------------------------------------------------------------------------

_SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "email", "username", "password", "password_hash", "hashed_password",
        "token", "access_token", "refresh_token", "id_token", "api_key",
        "secret", "secret_key", "private_key", "auth_token", "bearer",
        "ssn", "credit_card", "card_number", "cvv", "bank_account",
        "phone", "address", "date_of_birth", "dob",
    }
)

# Keywords in body text that suggest a login wall
_LOGIN_KEYWORDS: tuple[str, ...] = (
    "sign in",
    "log in",
    "login",
    "please login",
    "please sign in",
    "forgot password",
    "reset password",
    "create account",
    "register",
    "username",
    "password",
    "remember me",
)

# SPA shell indicators — root page body is tiny and structureless
_SPA_INDICATORS: tuple[str, ...] = (
    '<div id="root">',
    '<div id="app">',
    '<div id="application">',
    '<div id="main">',
    "window.__INITIAL_STATE__",
    "window.__NUXT__",
    "__next_router",
    "data-reactroot",
)

# Known docs path suffixes for open-docs detection
_DOCS_PATHS: frozenset[str] = frozenset(
    {"/swagger", "/swagger-ui", "/openapi.json", "/api-docs", "/redoc"}
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_signals(probe_set: ProbeSet) -> list[str]:
    """
    Extract all relevant signals from a ``ProbeSet``.

    Iterates over every ``ProbeResult`` in the set, applies all signal
    extraction rules, and returns a deduplicated, sorted list of signal
    label strings.

    Args:
        probe_set: The complete set of HTTP probe results for one domain.

    Returns:
        A sorted list of unique signal label strings.
    """
    signals: set[str] = set()

    for probe in probe_set.probes:
        signals.update(_extract_from_probe(probe, probe_set.domain))

    # Cross-probe signals (require seeing multiple probes together)
    signals.update(_extract_cross_probe_signals(probe_set))

    result = sorted(signals)
    if result:
        logger.debug("Signals for %s: %s", probe_set.domain, result)
    return result


# ---------------------------------------------------------------------------
# Per-probe extraction
# ---------------------------------------------------------------------------


def _extract_from_probe(probe: ProbeResult, domain: str) -> set[str]:
    """Extract signals from a single ProbeResult."""
    signals: set[str] = set()

    if not probe.is_successful and probe.error:
        return signals  # No signals from failed probes (error captured elsewhere)

    # --- Auth signals from status codes & headers ---
    signals.update(_extract_auth_header_signals(probe))
    signals.update(_extract_redirect_signals(probe, domain))
    signals.update(_extract_cookie_signals(probe))

    # --- Service-type signals from content ---
    signals.update(_extract_content_signals(probe))

    # --- HTML-specific signals ---
    if probe.is_html_response and probe.body_preview:
        signals.update(_extract_html_signals(probe))

    # --- JSON-specific signals ---
    if probe.is_json_response and probe.body_preview:
        signals.update(_extract_json_signals(probe))

    # --- GraphQL-specific signals ---
    if probe.path_category in ("graphql", "graphql_introspection"):
        signals.update(_extract_graphql_signals(probe))

    # --- Risk signals ---
    signals.update(_extract_risk_signals(probe))

    # --- API indicator headers ---
    signals.update(_extract_api_header_signals(probe))

    return signals


def _extract_auth_header_signals(probe: ProbeResult) -> set[str]:
    signals: set[str] = set()
    www_auth = (probe.response_headers.get("www-authenticate") or "").lower()

    if probe.status_code == 401:
        if "basic" in www_auth:
            signals.add(R_401_BASIC)
        elif "digest" in www_auth:
            signals.add(R_401_DIGEST)
        elif "bearer" in www_auth:
            signals.add(R_401_BEARER)
        else:
            # 401 without a recognised scheme — still auth
            signals.add(R_401_BEARER)  # Treat as bearer for scoring

    if probe.status_code == 403:
        signals.add(R_403_FORBIDDEN)

    return signals


def _extract_redirect_signals(probe: ProbeResult, domain: str) -> set[str]:
    signals: set[str] = set()

    # Build the full chain including the final URL
    full_chain = probe.redirect_chain + ([probe.final_url] if probe.redirect_chain else [])
    if not full_chain:
        return signals

    summary = classify_redirect_chain(full_chain, domain)

    if summary["has_auth_path"]:
        signals.add(R_AUTH_REDIRECT_PATH)
    if summary["is_external"]:
        signals.add(R_AUTH_REDIRECT_EXTERNAL)
    if summary["auth_provider_hit"]:
        signals.add(R_AUTH_REDIRECT_PROVIDER)

    # Also check the final URL directly
    if is_auth_path(probe.final_url.split("?")[0]):
        signals.add(R_AUTH_REDIRECT_PATH)
    if is_known_auth_provider(probe.final_url):
        signals.add(R_AUTH_REDIRECT_PROVIDER)

    return signals


def _extract_cookie_signals(probe: ProbeResult) -> set[str]:
    signals: set[str] = set()
    set_cookie = (probe.response_headers.get("set-cookie") or "").lower()

    session_patterns = ("session", "sess", "auth", "token", "jwt", "access_token")
    if any(p in set_cookie for p in session_patterns):
        signals.add(R_SESSION_COOKIE)

    return signals


def _extract_content_signals(probe: ProbeResult) -> set[str]:
    signals: set[str] = set()
    ct = (probe.content_type or "").lower()

    if "application/json" in ct or "application/ld+json" in ct:
        signals.add(R_JSON_CONTENT_TYPE)

    if "text/html" in ct:
        body = probe.body_preview
        if "<html" in body.lower():
            signals.add(R_HTML_RESPONSE)

    body_stripped = probe.body_preview.lstrip()
    if body_stripped.startswith(("{", "[")):
        signals.add(R_JSON_BODY)

    return signals


def _extract_html_signals(probe: ProbeResult) -> set[str]:
    """Extract signals from HTML body — uses simple string/regex to avoid bs4 overhead."""
    signals: set[str] = set()
    body_lower = probe.body_preview.lower()

    # Password field
    if 'type="password"' in body_lower or "type='password'" in body_lower:
        signals.add(R_PASSWORD_FIELD)

    # Login form — look for <form> elements with login-related actions
    form_actions = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', body_lower)
    login_form = any(is_auth_path(a) for a in form_actions)
    if login_form or (R_PASSWORD_FIELD in signals and "<form" in body_lower):
        signals.add(R_LOGIN_FORM)

    # Login keywords
    keyword_matches = sum(1 for kw in _LOGIN_KEYWORDS if kw in body_lower)
    if keyword_matches >= 2:  # Require at least 2 to reduce false positives
        signals.add(R_LOGIN_KEYWORD)

    # Swagger / OpenAPI / Redoc markers
    if "swagger" in body_lower:
        signals.add(R_SWAGGER_MARKER)
    if '"openapi"' in body_lower or "swagger-ui" in body_lower:
        signals.add(R_OPENAPI_MARKER)
    if "redoc" in body_lower and ("api" in body_lower or "swagger" in body_lower):
        signals.add(R_REDOC_MARKER)

    # SPA shell detection (short body + SPA indicators)
    body_text = probe.body_preview.strip()
    if len(body_text) < 600 and any(ind.lower() in body_lower for ind in _SPA_INDICATORS):
        signals.add(R_SPA_SHELL)

    return signals


def _extract_json_signals(probe: ProbeResult) -> set[str]:
    """Extract signals from JSON response bodies."""
    signals: set[str] = set()
    body = probe.body_preview

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        # Body snippet might be truncated — do string-level checks instead
        data = None

    if data is not None and isinstance(data, dict):
        # Check for sensitive field names
        _scan_json_for_sensitive(data, signals)

        # GraphQL-style response structure
        if "data" in data or "errors" in data:
            signals.add(R_GRAPHQL_RESPONSE)

    elif data is not None and isinstance(data, list) and len(data) > 0:
        # List response — check first item for sensitive fields
        first = data[0] if isinstance(data[0], dict) else {}
        _scan_json_for_sensitive(first, signals)

    # Swagger/OpenAPI spec detection in JSON
    body_lower = body.lower()
    if '"openapi"' in body_lower and '"paths"' in body_lower:
        signals.add(R_OPENAPI_MARKER)
    if '"swagger"' in body_lower and '"paths"' in body_lower:
        signals.add(R_SWAGGER_MARKER)

    return signals


def _scan_json_for_sensitive(obj: dict, signals: set[str]) -> None:
    """Recursively scan a dict for sensitive field names."""
    for key in obj:
        if isinstance(key, str) and key.lower() in _SENSITIVE_FIELD_NAMES:
            signals.add(R_SENSITIVE_FIELDS)
            return  # One hit is enough
    # Scan one level deep in nested dicts (avoid deep recursion)
    for val in obj.values():
        if isinstance(val, dict):
            for key in val:
                if isinstance(key, str) and key.lower() in _SENSITIVE_FIELD_NAMES:
                    signals.add(R_SENSITIVE_FIELDS)
                    return


def _extract_graphql_signals(probe: ProbeResult) -> set[str]:
    """Extract GraphQL-specific signals."""
    signals: set[str] = set()
    body = probe.body_preview.lower()

    if probe.path_category == "graphql_introspection":
        # This IS the introspection POST response
        if "__schema" in body or "__typename" in body:
            signals.add(R_GRAPHQL_INTROSPECTION)
        return signals

    # GET to a graphql path that responded successfully
    if probe.is_successful and probe.status_code not in (404, 405):
        signals.add(R_GRAPHQL_OPEN)

    if "__schema" in body or '"data"' in body:
        signals.add(R_GRAPHQL_RESPONSE)

    return signals


def _extract_risk_signals(probe: ProbeResult) -> set[str]:
    """Extract risk / exposure signals."""
    signals: set[str] = set()

    if not probe.is_successful:
        return signals

    # Open docs: docs path responded 200 with no auth signal on this probe
    if probe.path_category == "docs" and probe.status_code == 200:
        # We'll flag this; rule engine decides if it's truly open (no auth signals elsewhere)
        signals.add(R_OPEN_DOCS)

    # Open API: API path returned JSON data successfully
    if probe.path_category == "api" and probe.status_code == 200 and probe.is_json_response:
        body_stripped = probe.body_preview.lstrip()
        if body_stripped.startswith(("{", "[")):
            signals.add(R_OPEN_API_DATA)

    return signals


def _extract_api_header_signals(probe: ProbeResult) -> set[str]:
    """Extract API-indicator signals from response headers."""
    signals: set[str] = set()
    headers = probe.response_headers

    rate_limit_keys = [k for k in headers if k.startswith("x-ratelimit")]
    if rate_limit_keys:
        signals.add(R_RATE_LIMIT_HEADERS)

    cors_keys = [k for k in headers if k.startswith("access-control-allow")]
    if cors_keys:
        signals.add(R_CORS_HEADERS)

    return signals


# ---------------------------------------------------------------------------
# Cross-probe signals (requires looking across multiple probes)
# ---------------------------------------------------------------------------


def _extract_cross_probe_signals(probe_set: ProbeSet) -> set[str]:
    """
    Extract signals that require comparing probes across multiple paths.

    Currently detects:
      - R_GRAPHQL_INTROSPECTION if any introspection_post probe has schema data
    """
    signals: set[str] = set()

    for probe in probe_set.probes:
        if probe.path_category == "graphql_introspection":
            body = probe.body_preview.lower()
            if "__schema" in body and probe.status_code == 200:
                signals.add(R_GRAPHQL_INTROSPECTION)

    return signals
