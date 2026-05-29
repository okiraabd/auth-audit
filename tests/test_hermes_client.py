"""
tests/test_hermes_client.py — Unit tests for the Hermes Browser Agent client.
"""

import httpx
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from tier3.hermes_client import (
    HermesClient,
    HermesAPIError,
    HermesTimeoutError,
    _parse_hermes_response,
    _unknown_from_text,
)
from tier3.hermes_tasks import build_auth_check_task


@pytest.fixture
def mock_hermes_settings(monkeypatch):
    monkeypatch.setenv("HERMES_BASE_URL", "http://mock-hermes/v1")
    monkeypatch.setenv("HERMES_API_KEY", "test-key")
    monkeypatch.setenv("HERMES_TASK_TIMEOUT", "5")
    # Disable S3 so real .env credentials don't bleed into tests
    monkeypatch.setenv("S3_ENDPOINT", "")
    monkeypatch.setenv("S3_ACCESS_KEY", "")
    monkeypatch.setenv("S3_SECRET_KEY", "")
    # Force Settings to reload from the patched environment
    import config
    import importlib
    importlib.reload(config)
    yield
    # Reload again after test to restore production settings
    importlib.reload(config)


# ---------------------------------------------------------------------------
# hermes_tasks tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_build_auth_check_task():
    payload = build_auth_check_task(
        "example.com",
        "React SPA shell",
        {"verdict": "UNKNOWN", "service_type": "WEB_APP"}
    )
    assert payload["domain"] == "example.com"
    assert payload["url"] == "https://example.com"
    assert "SPA shell" in payload["instructions"]
    assert payload["context"]["service_type"] == "WEB_APP"


def test_build_auth_check_task_instructions_include_reason():
    payload = build_auth_check_task(
        "foo.bar", "SPA shell + GraphQL open", {"verdict": "GRAPHQL_OPEN", "service_type": "GRAPHQL"}
    )
    assert "GraphQL" in payload["instructions"]
    assert payload["context"]["tier1_verdict"] == "GRAPHQL_OPEN"


# ---------------------------------------------------------------------------
# parse_hermes_response tests
# ---------------------------------------------------------------------------

def test_parse_clean_json_block():
    content = '''
```json
{
  "verdict": "PROTECTED",
  "confidence": 90,
  "visual_evidence": "Login form seen",
  "interaction_steps": ["opened", "waited"],
  "auth_mechanisms_detected": ["login form"],
  "reasoning": "Login page visible",
  "screenshots": []
}
```
'''
    result = _parse_hermes_response(content, "example.com")
    assert result["verdict"] == "PROTECTED"
    assert result["confidence"] == 90


def test_parse_raw_json_no_fences():
    content = '{"verdict": "OPEN", "confidence": 70, "reasoning": "No auth seen"}'
    result = _parse_hermes_response(content, "example.com")
    assert result["verdict"] == "OPEN"


def test_parse_normalizes_unknown_verdict():
    content = '{"verdict": "TOTALLY_MADE_UP", "confidence": 50, "reasoning": "?"}'
    result = _parse_hermes_response(content, "example.com")
    assert result["verdict"] == "UNKNOWN"


def test_parse_strips_think_blocks():
    content = '<think>Internal reasoning here</think>\n```json\n{"verdict": "PROTECTED", "confidence": 88, "reasoning": "auth required"}\n```'
    result = _parse_hermes_response(content, "example.com")
    assert result["verdict"] == "PROTECTED"


def test_parse_fills_missing_fields():
    content = '{"verdict": "OPEN"}'
    result = _parse_hermes_response(content, "example.com")
    assert "confidence" in result
    assert "interaction_steps" in result
    assert isinstance(result["interaction_steps"], list)


def test_parse_no_json_returns_unknown():
    result = _parse_hermes_response("Sorry, I could not analyze this page.", "example.com")
    assert result["verdict"] == "UNKNOWN"
    assert result["confidence"] == 0


# ---------------------------------------------------------------------------
# HermesClient connection fallback test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hermes_client_fallback_on_connection_error(mock_hermes_settings):
    # http://mock-hermes will fail to connect — should gracefully return fallback
    async with HermesClient() as client:
        result = await client.submit_task({"domain": "example.com", "url": "https://example.com"})

    assert result["verdict"] == "UNKNOWN"
    assert "Hermes browser analysis failed" in result["reasoning"]
    assert "_error" in result


@pytest.mark.asyncio
async def test_hermes_client_timeout_handled(mock_hermes_settings):
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.TimeoutException("Mock timeout")

        async with HermesClient() as client:
            result = await client.submit_task({"domain": "example.com", "url": "https://example.com"})

    assert result["verdict"] == "UNKNOWN"
    assert "_error" in result


@pytest.mark.asyncio
async def test_hermes_client_success(mock_hermes_settings):
    raw_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": '{"verdict": "PROTECTED", "confidence": 95, "visual_evidence": "Login form visible", "interaction_steps": ["opened"], "auth_mechanisms_detected": ["login form"], "reasoning": "Auth required", "screenshots": []}'
                }
            }
        ]
    }
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = raw_response
        mock_post.return_value = mock_resp

        async with HermesClient() as client:
            result = await client.submit_task({"domain": "example.com", "url": "https://example.com"})

    assert result["verdict"] == "PROTECTED"
    assert result["confidence"] == 95
    assert result["visual_evidence"] == "Login form visible"
