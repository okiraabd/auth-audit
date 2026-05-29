"""
tier2/llm_client.py — Async client for the Local LLM OpenAI-compatible API.

Wraps the Local LLM endpoint with a thin, typed interface for chat completions.
Supports both context-manager usage (shared client lifecycle) and one-shot
calls (auto-creates and closes the client per call).

Custom exceptions
-----------------
  LLMAPIError    — Non-2xx HTTP response from the endpoint.
  LLMParseError  — Unexpected response shape from the endpoint.
  LLMTimeoutError — Request exceeded the configured timeout.

Usage — context manager (preferred for multiple calls)::

    async with LLMClient() as client:
        response = await client.chat_completion(messages)

Usage — one-shot::

    client = LLMClient()
    response = await client.chat_completion(messages)
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from utils.retry import retry_async

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class LLMAPIError(Exception):
    """Raised when the Local LLM API returns a non-2xx HTTP status."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"Local LLM API returned HTTP {status_code}: {body[:200]}")


class LLMParseError(Exception):
    """Raised when the API response does not match the expected OpenAI chat schema."""


class LLMTimeoutError(Exception):
    """Raised when the Local LLM request times out."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class LLMClient:
    """
    Async client for the Local LLM OpenAI-compatible chat completions endpoint.

    Configuration is read lazily from ``config.settings`` at instantiation,
    so tests can override settings before creating the client.
    """

    def __init__(self) -> None:
        from config import settings  # lazy import

        self._base_url = str(settings.llm_base_url).rstrip("/")
        self._model = settings.llm_model
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature
        self._api_key = settings.llm_api_key
        self._retry_attempts = settings.llm_retry_attempts
        self._timeout = httpx.Timeout(
            connect=10.0,
            read=120.0,  # LLM responses can be slow
            write=10.0,
            pool=10.0,
        )
        self._http_client: httpx.AsyncClient | None = None

    # -------------------------------------------------------------------------
    # Context manager — shared client lifecycle
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> "LLMClient":
        self._http_client = self._build_http_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        extra_body: dict | None = None,
    ) -> dict:
        """
        Send a chat completion request and return the parsed JSON response.

        Args:
            messages:    List of ``{"role": "...", "content": "..."}`` dicts.
            temperature: Override the configured temperature for this call.
            max_tokens:  Override the configured max_tokens for this call.
            extra_body:  Additional fields merged into the request body
                         (e.g. ``{"stream": false}``).

        Returns:
            The full parsed JSON response dict (OpenAI chat completion shape).

        Raises:
            LLMAPIError:    On non-2xx HTTP responses.
            LLMTimeoutError: On request timeout.
            LLMParseError:  On unexpected response shape.
        """
        payload = self._build_payload(messages, temperature, max_tokens, extra_body)

        if self._http_client:
            # Context-manager mode — reuse the shared client
            return await self._post(self._http_client, payload)
        else:
            # One-shot mode — create and close a client for this single call
            async with self._build_http_client() as client:
                return await self._post(client, payload)

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _build_http_client(self) -> httpx.AsyncClient:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return httpx.AsyncClient(
            timeout=self._timeout,
            headers=headers,
            verify=False,  # Internal Local LLM endpoints may use self-signed TLS
        )

    def _build_payload(
        self,
        messages: list[dict],
        temperature: float | None,
        max_tokens: int | None,
        extra_body: dict | None,
    ) -> dict:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self._temperature,
            "max_tokens": max_tokens if max_tokens is not None else self._max_tokens,
            "stream": False,
        }
        if extra_body:
            payload.update(extra_body)
        return payload

    async def _post(self, client: httpx.AsyncClient, payload: dict) -> dict:
        """Send the POST request with retry, returning the parsed response dict."""
        url = f"{self._base_url}/chat/completions"
        attempts = self._retry_attempts

        async def _call() -> dict:
            try:
                response = await client.post(url, json=payload)
            except httpx.TimeoutException as exc:
                raise LLMTimeoutError(f"Local LLM request timed out: {exc}") from exc

            if response.status_code != 200:
                raise LLMAPIError(response.status_code, response.text)

            try:
                data = response.json()
            except Exception as exc:
                raise LLMParseError(f"Local LLM returned non-JSON body: {exc}") from exc

            # Validate OpenAI shape minimally
            if "choices" not in data or not data["choices"]:
                raise LLMParseError(f"Local LLM response missing 'choices': {data}")

            return data

        return await retry_async(
            _call,
            attempts=attempts,
            wait_base=1.0,
            retryable=(httpx.TransportError, ConnectionError, OSError),
        )
