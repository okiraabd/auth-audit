"""
tests/test_rule_engine.py — Unit tests for the Tier 1 deterministic rule engine.

Tests are offline — ProbeResult and ProbeSet are constructed directly from
fixture data; no network I/O.

Coverage:
  - UNREACHABLE when all probes fail
  - PROTECTED from 401 Basic / Digest / Bearer
  - PROTECTED from known auth provider redirect
  - PROTECTED from auth path redirect (no API signals)
  - PARTIAL when auth redirect + JSON API signals coexist
  - PROTECTED from password field + login form
  - GRAPHQL_CRITICAL from introspection data
  - OPEN_API_CRITICAL from API data + sensitive fields
  - OPEN_DOCS from reachable docs path (no auth)
  - OPEN_API from API JSON without sensitive data
  - GRAPHQL_OPEN from reachable graphql path without introspection
  - PARTIAL from weak signals (403, login keyword)
  - UNKNOWN from SPA shell
  - Service type classification from signal sets
  - rule_score is always 0–100
  - needs_llm is True when score < threshold
  - triggered_rules contains expected signals
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from models.probes import ProbeResult, ProbeSet
from tier1.rule_engine import evaluate
from tier1.signal_extractor import (
    R_401_BASIC,
    R_401_BEARER,
    R_401_DIGEST,
    R_403_FORBIDDEN,
    R_AUTH_REDIRECT_PATH,
    R_AUTH_REDIRECT_PROVIDER,
    R_GRAPHQL_INTROSPECTION,
    R_GRAPHQL_OPEN,
    R_HTML_RESPONSE,
    R_JSON_BODY,
    R_JSON_CONTENT_TYPE,
    R_LOGIN_FORM,
    R_LOGIN_KEYWORD,
    R_OPEN_API_DATA,
    R_OPEN_DOCS,
    R_PASSWORD_FIELD,
    R_SENSITIVE_FIELDS,
    R_SESSION_COOKIE,
    R_SPA_SHELL,
    R_SWAGGER_MARKER,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_probe(
    path: str = "/",
    status: int = 200,
    content_type: str = "text/html",
    www_auth: str | None = None,
    body: str = "<html><body>Hello</body></html>",
    redirect_chain: list[str] | None = None,
    final_url: str | None = None,
    set_cookie: str | None = None,
    error: str | None = None,
    category: str = "web",
) -> ProbeResult:
    headers: dict[str, str] = {"content-type": content_type}
    if www_auth:
        headers["www-authenticate"] = www_auth
    if set_cookie:
        headers["set-cookie"] = set_cookie

    return ProbeResult(
        requested_url=f"https://example.internal{path}",
        final_url=final_url or f"https://example.internal{path}",
        redirect_chain=redirect_chain or [],
        status_code=status if not error else None,
        response_headers=headers,
        content_type=content_type if not error else None,
        body_preview=body if not error else "",
        path_category=category,
        path=path,
        error=error,
    )


def make_probe_set(probes: list[ProbeResult], domain: str = "example.internal") -> ProbeSet:
    return ProbeSet(domain=domain, probes=probes)


def all_error_probe_set() -> ProbeSet:
    probes = [make_probe(path=p, error="ConnectError", category="web") for p in ["/", "/login", "/admin"]]
    return make_probe_set(probes)


# ---------------------------------------------------------------------------
# 1. UNREACHABLE
# ---------------------------------------------------------------------------


class TestUnreachable:
    def test_all_probes_failed(self):
        result = evaluate([], all_error_probe_set())
        assert result["rule_verdict"] == "UNREACHABLE"
        assert result["rule_score"] >= 90
        assert result["needs_llm"] is False

    def test_unreachable_needs_no_llm(self):
        result = evaluate([], all_error_probe_set())
        assert result["needs_llm"] is False


# ---------------------------------------------------------------------------
# 2. PROTECTED — strong auth signals
# ---------------------------------------------------------------------------


class TestProtectedStrong:
    def test_401_basic_auth(self):
        probe = make_probe(path="/", status=401, www_auth="Basic realm=Restricted")
        ps = make_probe_set([probe])
        result = evaluate([R_401_BASIC], ps)
        assert result["rule_verdict"] == "PROTECTED"
        assert result["rule_score"] >= 90
        assert result["needs_llm"] is False
        assert R_401_BASIC in result["triggered_rules"]

    def test_401_digest_auth(self):
        probe = make_probe(path="/", status=401, www_auth="Digest realm=Admin")
        ps = make_probe_set([probe])
        result = evaluate([R_401_DIGEST], ps)
        assert result["rule_verdict"] == "PROTECTED"
        assert result["needs_llm"] is False

    def test_401_bearer_auth(self):
        probe = make_probe(path="/api", status=401, www_auth="Bearer")
        ps = make_probe_set([probe])
        result = evaluate([R_401_BEARER], ps)
        assert result["rule_verdict"] == "PROTECTED"
        assert result["needs_llm"] is False

    def test_auth_provider_redirect(self):
        probe = make_probe(
            path="/",
            status=302,
            redirect_chain=["https://keycloak.internal/auth/realms/master/protocol/openid-connect/auth"],
            final_url="https://keycloak.internal/auth/realms/master/protocol/openid-connect/auth",
        )
        ps = make_probe_set([probe])
        result = evaluate([R_AUTH_REDIRECT_PROVIDER], ps)
        assert result["rule_verdict"] == "PROTECTED"
        assert result["needs_llm"] is False
        assert R_AUTH_REDIRECT_PROVIDER in result["triggered_rules"]

    def test_password_field_and_login_form(self):
        body = '<html><form action="/login"><input type="password" /></form></html>'
        probe = make_probe(path="/", status=200, body=body)
        ps = make_probe_set([probe])
        result = evaluate([R_PASSWORD_FIELD, R_LOGIN_FORM, R_HTML_RESPONSE], ps)
        assert result["rule_verdict"] == "PROTECTED"
        assert result["service_type_guess"] == "WEB_APP"


# ---------------------------------------------------------------------------
# 3. PROTECTED — moderate auth signals
# ---------------------------------------------------------------------------


class TestProtectedModerate:
    def test_auth_redirect_path_no_api(self):
        probe = make_probe(path="/", status=302, final_url="https://example.internal/login")
        ps = make_probe_set([probe])
        result = evaluate([R_AUTH_REDIRECT_PATH, R_HTML_RESPONSE], ps)
        assert result["rule_verdict"] == "PROTECTED"

    def test_auth_redirect_path_with_json_becomes_partial(self):
        """Redirect to /login but also seeing JSON API — mixed service."""
        probe = make_probe(path="/", status=302, final_url="https://example.internal/login")
        api_probe = make_probe(path="/api", status=200, content_type="application/json", body='{"data":[]}', category="api")
        ps = make_probe_set([probe, api_probe])
        result = evaluate(
            [R_AUTH_REDIRECT_PATH, R_JSON_BODY, R_JSON_CONTENT_TYPE, R_HTML_RESPONSE],
            ps,
        )
        assert result["rule_verdict"] == "PARTIAL"
        assert result["needs_llm"] is True
        assert result["service_type_guess"] == "MIXED"


# ---------------------------------------------------------------------------
# 4. Open exposure verdicts
# ---------------------------------------------------------------------------


class TestOpenExposure:
    def test_graphql_introspection_critical(self):
        probe = make_probe(
            path="/graphql[introspection_post]",
            status=200,
            content_type="application/json",
            body='{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}',
            category="graphql_introspection",
        )
        ps = make_probe_set([probe])
        result = evaluate([R_GRAPHQL_INTROSPECTION], ps)
        assert result["rule_verdict"] == "GRAPHQL_CRITICAL"
        assert result["service_type_guess"] == "GRAPHQL"
        assert result["needs_llm"] is False

    def test_open_api_with_sensitive_fields(self):
        probe = make_probe(
            path="/api/v1",
            status=200,
            content_type="application/json",
            body='[{"email":"alice@corp.com","token":"abc123"}]',
            category="api",
        )
        ps = make_probe_set([probe])
        result = evaluate([R_OPEN_API_DATA, R_SENSITIVE_FIELDS, R_JSON_BODY, R_JSON_CONTENT_TYPE], ps)
        assert result["rule_verdict"] == "OPEN_API_CRITICAL"
        assert result["needs_llm"] is False

    def test_open_docs_accessible(self):
        probe = make_probe(
            path="/swagger",
            status=200,
            content_type="text/html",
            body='<html>swagger-ui...</html>',
            category="docs",
        )
        ps = make_probe_set([probe])
        result = evaluate([R_OPEN_DOCS, R_SWAGGER_MARKER, R_HTML_RESPONSE], ps)
        assert result["rule_verdict"] == "OPEN_DOCS"
        assert result["needs_llm"] is False

    def test_open_api_without_sensitive(self):
        probe = make_probe(
            path="/api",
            status=200,
            content_type="application/json",
            body='{"version": "1.0", "status": "ok"}',
            category="api",
        )
        ps = make_probe_set([probe])
        result = evaluate([R_OPEN_API_DATA, R_JSON_BODY, R_JSON_CONTENT_TYPE], ps)
        assert result["rule_verdict"] == "OPEN_API"
        assert result["needs_llm"] is True

    def test_graphql_open_without_introspection(self):
        probe = make_probe(path="/graphql", status=200, content_type="application/json", category="graphql")
        ps = make_probe_set([probe])
        result = evaluate([R_GRAPHQL_OPEN], ps)
        assert result["rule_verdict"] == "GRAPHQL_OPEN"
        assert result["needs_llm"] is True


# ---------------------------------------------------------------------------
# 5. PARTIAL and UNKNOWN
# ---------------------------------------------------------------------------


class TestPartialAndUnknown:
    def test_403_forbidden_only(self):
        probe = make_probe(path="/", status=403)
        ps = make_probe_set([probe])
        result = evaluate([R_403_FORBIDDEN], ps)
        assert result["rule_verdict"] == "PARTIAL"
        assert result["needs_llm"] is True

    def test_login_keyword_only(self):
        probe = make_probe(path="/", status=200, body="<html>please sign in to continue</html>")
        ps = make_probe_set([probe])
        result = evaluate([R_LOGIN_KEYWORD, R_HTML_RESPONSE], ps)
        assert result["rule_verdict"] == "PARTIAL"
        assert result["needs_llm"] is True

    def test_spa_shell_is_unknown(self):
        probe = make_probe(path="/", status=200, body='<div id="root"></div>')
        ps = make_probe_set([probe])
        result = evaluate([R_SPA_SHELL, R_HTML_RESPONSE], ps)
        assert result["rule_verdict"] == "UNKNOWN"
        assert result["needs_llm"] is True

    def test_no_signals_is_unknown(self):
        probe = make_probe(path="/", status=200)
        ps = make_probe_set([probe])
        result = evaluate([], ps)
        assert result["needs_llm"] is True


# ---------------------------------------------------------------------------
# 6. Output schema validation
# ---------------------------------------------------------------------------


class TestOutputSchema:
    def test_score_always_in_range(self):
        for signals in ([], [R_401_BASIC], [R_SPA_SHELL], [R_GRAPHQL_INTROSPECTION]):
            probe = make_probe()
            ps = make_probe_set([probe])
            result = evaluate(list(signals), ps)
            assert 0 <= result["rule_score"] <= 100, f"Score out of range for signals {signals}"

    def test_triggered_rules_is_sorted_list(self):
        probe = make_probe(path="/", status=401, www_auth="Bearer")
        ps = make_probe_set([probe])
        result = evaluate([R_401_BEARER, R_JSON_BODY], ps)
        assert isinstance(result["triggered_rules"], list)
        assert result["triggered_rules"] == sorted(result["triggered_rules"])

    def test_all_required_keys_present(self):
        result = evaluate([R_401_BASIC], make_probe_set([make_probe()]))
        required = {"service_type_guess", "rule_score", "rule_verdict", "triggered_rules", "needs_llm", "ambiguity_reason"}
        assert required.issubset(result.keys())

    def test_low_score_forces_needs_llm(self):
        """Any verdict with score < 65 must set needs_llm=True."""
        probe = make_probe(path="/", status=200)
        ps = make_probe_set([probe])
        result = evaluate([R_HTML_RESPONSE], ps)
        if result["rule_score"] < 65:
            assert result["needs_llm"] is True


# ---------------------------------------------------------------------------
# 7. Service type classification
# ---------------------------------------------------------------------------


class TestServiceType:
    def test_graphql_signals_give_graphql_type(self):
        result = evaluate([R_GRAPHQL_INTROSPECTION], make_probe_set([make_probe()]))
        assert result["service_type_guess"] == "GRAPHQL"

    def test_json_only_signals_give_rest_api(self):
        result = evaluate([R_401_BEARER, R_JSON_CONTENT_TYPE], make_probe_set([make_probe()]))
        assert result["service_type_guess"] == "REST_API"

    def test_html_only_gives_web_app(self):
        result = evaluate([R_PASSWORD_FIELD, R_LOGIN_FORM, R_HTML_RESPONSE], make_probe_set([make_probe()]))
        assert result["service_type_guess"] == "WEB_APP"

    def test_json_plus_html_gives_mixed(self):
        result = evaluate([R_AUTH_REDIRECT_PATH, R_JSON_BODY, R_HTML_RESPONSE], make_probe_set([make_probe()]))
        assert result["service_type_guess"] == "MIXED"
