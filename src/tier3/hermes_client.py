"""
tier3/hermes_client.py — Client for the Hermes Browser Automation Agent.

Hermes is an OpenAI-compatible chat API backed by a Qwen agent that has
real browser capabilities (navigate, click, scroll, screenshot). We send it
a structured prompt asking it to visit a domain and determine its auth status.

The agent's response is a JSON string embedded in its chat reply, which we parse
to extract the structured Tier 3 verdict.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from utils.retry import retry_async

logger = logging.getLogger(__name__)


class HermesAPIError(Exception):
    """Raised when the Hermes API returns a non-2xx HTTP status."""


class HermesTimeoutError(Exception):
    """Raised when the Hermes request times out."""


# System prompt instructing Hermes how to behave as an auth auditor
_SYSTEM_PROMPT = """\
You are an expert web security auditor performing an automated authentication detection audit.

Your task is to visit a given URL, fully render it with JavaScript, and determine if the service requires authentication.

BROWSER STEPS (execute in order):
1. Open the URL and wait for full JS rendering (at least 3 seconds).
2. Take a screenshot of the initial view.
3. If the page is an SPA shell (<div id="root"></div>), wait an additional 3 seconds.
4. If you see "Login", "Sign in", or "Get Started" — click it and observe the result.
5. Take a final screenshot after any interactions.

VERDICT GUIDE:
- PROTECTED        : Login form visible, redirected to /login, or 401/403 with auth headers
- PARTIAL          : Some paths open, some require auth
- OPEN             : Public content served with no login required
- OPEN_API         : API endpoint responds to requests without auth
- GRAPHQL_OPEN     : GraphQL endpoint reachable (no introspection confirmed)
- GRAPHQL_CRITICAL : GraphQL introspection query succeeded without auth
- UNKNOWN          : Cannot determine — service broken, empty, or inconclusive

CRITICAL OUTPUT RULE:
Your FINAL output must be ONLY the raw JSON object below. No markdown code fences. No ```json. No explanation before or after it.
Start your final answer with { and end with }

{
  "verdict": "PROTECTED|OPEN|OPEN_API|OPEN_DOCS|GRAPHQL_OPEN|GRAPHQL_CRITICAL|PARTIAL|UNKNOWN",
  "confidence": <int 0-100>,
  "visual_evidence": "<one-line description of what you saw>",
  "interaction_steps": ["<step 1>", "<step 2>"],
  "auth_mechanisms_detected": ["<e.g. login form>", "<e.g. OAuth redirect>"],
  "reasoning": "<clear explanation of your verdict>",
  "screenshots": ["<S3 URL if uploaded, otherwise screenshot filename>"]
}
"""


class HermesClient:
    """
    Async client for the Hermes Browser Agent (OpenAI-compatible chat API).

    Hermes understands browser automation instructions embedded in chat prompts.
    We send a structured system+user prompt, and parse the JSON block from its reply.
    """

    def __init__(self) -> None:
        from config import settings

        self._base_url = str(settings.hermes_base_url).rstrip("/")
        self._api_key = settings.hermes_api_key
        # Browser tasks take time — use a very generous read timeout
        self._timeout = httpx.Timeout(
            connect=10.0,
            read=settings.hermes_task_timeout,
            write=10.0,
            pool=10.0,
        )
        self._http_client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "HermesClient":
        self._http_client = self._build_http_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def _build_http_client(self) -> httpx.AsyncClient:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return httpx.AsyncClient(
            timeout=self._timeout,
            headers=headers,
            verify=False,
        )

    async def submit_task(self, task_payload: dict) -> dict:
        """
        Submit a browser task and wait for its result.

        task_payload should contain:
            domain: str
            url: str
            instructions: str (context from Tier 2)
            context: dict (tier1/tier2 hints)

        Returns:
            A structured verdict dict.
        """
        if self._http_client:
            return await self._execute(self._http_client, task_payload)
        else:
            async with self._build_http_client() as client:
                return await self._execute(client, task_payload)

    async def _execute(self, client: httpx.AsyncClient, payload: dict) -> dict:
        endpoint = f"{self._base_url}/chat/completions"
        domain = payload.get("domain", "unknown")
        url = payload.get("url", f"https://{domain}")
        instructions = payload.get("instructions", "")
        context = payload.get("context", {})

        user_message = (
            f"Domain: {domain}\n"
            f"URL: {url}\n\n"
            f"Additional context from our static analysis:\n"
            f"- Tier 1 verdict: {context.get('tier1_verdict', 'UNKNOWN')}\n"
            f"- Service type: {context.get('service_type', 'UNKNOWN')}\n"
            f"- Escalation reason: {instructions}\n"
        )

        # Inject S3 upload instructions when configured
        s3_block = payload.get("_s3_instructions")
        if s3_block:
            user_message += f"\n{s3_block}\n"

        user_message += "\nPlease visit this URL, analyze the authentication status, and return your findings in the exact JSON format specified."

        chat_payload = {
            "model": "hermes",
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": 4096,
            "temperature": 0.1,
            "stream": False,
        }

        async def _call() -> dict:
            try:
                response = await client.post(endpoint, json=chat_payload)
            except httpx.TimeoutException as exc:
                raise HermesTimeoutError(f"Hermes browser task timed out: {exc}") from exc

            if response.status_code != 200:
                raise HermesAPIError(f"HTTP {response.status_code}: {response.text[:300]}")

            try:
                data = response.json()
            except Exception as exc:
                raise HermesAPIError(f"Invalid JSON from Hermes: {exc}") from exc

            choices = data.get("choices", [])
            if not choices:
                raise HermesAPIError(f"Hermes returned no choices: {data}")

            content = choices[0].get("message", {}).get("content", "")
            logger.debug("Hermes raw response for %s:\n%s", domain, content[:500])

            return _parse_hermes_response(content, domain)

        try:
            return await retry_async(
                _call,
                attempts=2,
                wait_base=3.0,
                retryable=(httpx.TransportError, ConnectionError),
            )
        except Exception as exc:
            logger.warning("Hermes failed for %s: %s", domain, exc)
            return self._fallback(str(exc))

    def _fallback(self, error_msg: str) -> dict:
        """Return a safe fallback structure if Hermes is unreachable or fails."""
        return {
            "verdict": "UNKNOWN",
            "confidence": 0,
            "visual_evidence": None,
            "interaction_steps": [],
            "auth_mechanisms_detected": [],
            "reasoning": f"Hermes browser analysis failed: {error_msg}",
            "screenshots": [],
            "_error": error_msg,
        }


def _parse_hermes_response(content: str, domain: str) -> dict:
    """
    Parse Hermes chat response and extract the structured JSON verdict.

    Hermes may wrap the JSON in a markdown code block or include explanation text.
    We extract the outermost JSON object and validate its shape.
    """
    # Strip <think>...</think> blocks (Qwen3 reasoning)
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    # Find JSON block (either raw or inside ```json ... ```)
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if json_match:
        json_str = json_match.group(1)
    else:
        # Try to find raw JSON object
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        json_str = json_match.group(0) if json_match else None

    if not json_str:
        # Last resort: try to extract any valid JSON from the raw text
        try:
            start = content.index("{")
            end = content.rindex("}") + 1
            json_str = content[start:end]
        except ValueError:
            logger.warning("Hermes returned no JSON block for %s — treating as UNKNOWN", domain)
            return _unknown_from_text(content)

    try:
        result = json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.warning("Hermes returned malformed JSON for %s: %s", domain, exc)
        return _unknown_from_text(content)

    # Normalize verdict
    valid_verdicts = {
        "PROTECTED", "OPEN", "OPEN_API", "OPEN_DOCS",
        "GRAPHQL_OPEN", "GRAPHQL_CRITICAL", "PARTIAL", "UNKNOWN"
    }
    verdict = str(result.get("verdict", "UNKNOWN")).upper()
    if verdict not in valid_verdicts:
        verdict = "UNKNOWN"
    result["verdict"] = verdict

    # Ensure required fields exist
    result.setdefault("confidence", 50)
    result.setdefault("visual_evidence", None)
    result.setdefault("interaction_steps", [])
    result.setdefault("auth_mechanisms_detected", [])
    result.setdefault("reasoning", "No reasoning provided.")
    result.setdefault("screenshots", [])

    return result


def _unknown_from_text(content: str) -> dict:
    """Fallback when JSON parsing fails — preserve the text as reasoning."""
    return {
        "verdict": "UNKNOWN",
        "confidence": 0,
        "visual_evidence": None,
        "interaction_steps": [],
        "auth_mechanisms_detected": [],
        "reasoning": content[:500] if content else "No response from Hermes.",
        "screenshots": [],
        # Mark as error so assembler skips T3 override
        "_error": "Hermes response did not contain a parseable JSON block.",
        "_parse_error": True,
    }
