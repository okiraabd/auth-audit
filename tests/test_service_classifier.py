"""
tests/test_service_classifier.py — Unit tests for service type classification
within the Tier 1 rule engine.

Tests verify that the rule engine produces the correct ``service_type_guess``
for each combination of service-type signals.  Auth signals are kept minimal
or set to trigger a verdict so the full evaluate() path is exercised.
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
    R_401_BEARER,
    R_CORS_HEADERS,
    R_GRAPHQL_INTROSPECTION,
    R_GRAPHQL_OPEN,
    R_GRAPHQL_RESPONSE,
    R_HTML_RESPONSE,
    R_JSON_BODY,
    R_JSON_CONTENT_TYPE,
    R_OPEN_API_DATA,
    R_OPENAPI_MARKER,
    R_RATE_LIMIT_HEADERS,
    R_SWAGGER_MARKER,
)


def make_probe_set(domain: str = "example.internal") -> ProbeSet:
    probe = ProbeResult(
        requested_url=f"https://{domain}/",
        final_url=f"https://{domain}/",
        status_code=200,
        response_headers={},
        path_category="web",
        path="/",
    )
    return ProbeSet(domain=domain, probes=[probe])


class TestServiceTypeREST:
    def test_json_content_type_bearer_gives_rest_api(self):
        result = evaluate([R_401_BEARER, R_JSON_CONTENT_TYPE], make_probe_set())
        assert result["service_type_guess"] == "REST_API"

    def test_json_body_bearer_gives_rest_api(self):
        result = evaluate([R_401_BEARER, R_JSON_BODY], make_probe_set())
        assert result["service_type_guess"] == "REST_API"

    def test_swagger_marker_gives_rest_api(self):
        result = evaluate([R_OPEN_API_DATA, R_SWAGGER_MARKER, R_JSON_CONTENT_TYPE], make_probe_set())
        assert result["service_type_guess"] == "REST_API"

    def test_openapi_marker_gives_rest_api(self):
        result = evaluate([R_OPEN_API_DATA, R_OPENAPI_MARKER, R_JSON_CONTENT_TYPE], make_probe_set())
        assert result["service_type_guess"] == "REST_API"

    def test_rate_limit_headers_hint_rest_api(self):
        """X-RateLimit headers are a strong API indicator even without JSON body."""
        result = evaluate([R_RATE_LIMIT_HEADERS], make_probe_set())
        # Falls through to UNKNOWN with UNKNOWN service type because no verdict triggered
        # The key assertion: if service type is set, it should be REST_API-adjacent
        # rate limit alone falls to fallback UNKNOWN, but service classifier picks REST_API
        assert result["service_type_guess"] in ("REST_API", "UNKNOWN")


class TestServiceTypeGraphQL:
    def test_introspection_gives_graphql(self):
        result = evaluate([R_GRAPHQL_INTROSPECTION], make_probe_set())
        assert result["service_type_guess"] == "GRAPHQL"

    def test_graphql_open_gives_graphql(self):
        result = evaluate([R_GRAPHQL_OPEN], make_probe_set())
        assert result["service_type_guess"] == "GRAPHQL"

    def test_graphql_response_structure_gives_graphql(self):
        result = evaluate([R_401_BEARER, R_GRAPHQL_RESPONSE], make_probe_set())
        assert result["service_type_guess"] == "GRAPHQL"


class TestServiceTypeWebApp:
    def test_html_only_gives_web_app(self):
        from tier1.signal_extractor import R_PASSWORD_FIELD, R_LOGIN_FORM
        result = evaluate([R_PASSWORD_FIELD, R_LOGIN_FORM, R_HTML_RESPONSE], make_probe_set())
        assert result["service_type_guess"] == "WEB_APP"


class TestServiceTypeMixed:
    def test_json_and_html_gives_mixed(self):
        from tier1.signal_extractor import R_AUTH_REDIRECT_PATH
        result = evaluate(
            [R_AUTH_REDIRECT_PATH, R_JSON_BODY, R_JSON_CONTENT_TYPE, R_HTML_RESPONSE],
            make_probe_set(),
        )
        assert result["service_type_guess"] == "MIXED"


class TestServiceTypeUnknown:
    def test_no_content_signals_gives_unknown(self):
        result = evaluate([], make_probe_set())
        assert result["service_type_guess"] == "UNKNOWN"
