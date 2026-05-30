"""
prober/http_prober.py — Asynchronous HTTP probe executor (Data Gathering).

Probes each domain across all paths defined by ``prober.path_strategy``,
captures raw HTTP signal data, and returns a ``ProbeSet`` per domain.

Design decisions:
  - One shared ``httpx.AsyncClient`` for the full pipeline run (connection
    pooling reduces TCP handshake overhead across hundreds of domains).
  - ``asyncio.Semaphore`` limits concurrency to ``config.prober_concurrency``.
  - SSL verification is disabled (``verify=False``) because many internal
    reverse-proxy hosts use self-signed or wildcard certificates.
  - Body is read up to ``config.body_preview_bytes`` — the client downloads
    the full response but only stores a preview to control memory usage.
  - GraphQL introspection POST is issued after a successful GET to any
    GraphQL path, to detect open introspection endpoints.
  - All network errors are caught and stored in ``ProbeResult.error`` —
    they never propagate as exceptions.
"""

from __future__ import annotations

import asyncio
import logging
import time
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

import httpx

from config import settings
from models.domain import Domain
from models.probes import ProbeResult, ProbeSet
from prober.path_strategy import classify_path, get_all_paths, is_graphql_path
from utils.retry import with_http_retry
from utils.urls import build_probe_url

logger = logging.getLogger(__name__)

# GraphQL introspection query — minimal schema probe
_GRAPHQL_INTROSPECTION = (
    '{"query":"{ __schema { queryType { name } types { name kind } } }"}'
)


# ---------------------------------------------------------------------------
# Client lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _make_client() -> AsyncIterator[httpx.AsyncClient]:
    """Yield a configured async httpx client, then close it on exit."""
    # Suppress the InsecureRequestWarning that httpx raises for verify=False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=settings.http_timeout,
                read=settings.http_timeout,
                write=settings.http_timeout,
                pool=settings.http_timeout,
            ),
            follow_redirects=True,
            max_redirects=settings.http_max_redirects,
            verify=False,  # Internal services often use self-signed / wildcard certs
            headers={"User-Agent": settings.http_user_agent},
            limits=httpx.Limits(
                max_connections=settings.prober_concurrency * 2,
                max_keepalive_connections=settings.prober_concurrency,
            ),
        ) as client:
            yield client


# ---------------------------------------------------------------------------
# Single-path probe
# ---------------------------------------------------------------------------


@with_http_retry()
async def _probe_one(
    client: httpx.AsyncClient,
    domain: str,
    path: str,
    scheme: str,
) -> ProbeResult:
    """
    Probe a single (domain, path) pair and return a ProbeResult.

    All exceptions are caught and stored in ``ProbeResult.error`` — this
    function never raises.
    """
    url = build_probe_url(domain, path, scheme)
    category = classify_path(path)
    t_start = time.monotonic()

    try:
        response = await client.get(url)
        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)

        # Redirect chain: every intermediate response URL (excluding final)
        redirect_chain = [str(r.url) for r in response.history]

        # Headers — lowercase keys for consistent signal extraction
        headers: dict[str, str] = {k.lower(): v for k, v in response.headers.items()}

        # Body preview — truncate without breaking the decode
        raw_body = response.content
        preview_bytes = raw_body[: settings.body_preview_bytes]
        body_preview = preview_bytes.decode("utf-8", errors="replace")

        # Response size from Content-Length header if available
        cl = headers.get("content-length", "")
        response_size = int(cl) if cl.isdigit() else len(raw_body)

        return ProbeResult(
            requested_url=url,
            final_url=str(response.url),
            redirect_chain=redirect_chain,
            status_code=response.status_code,
            response_headers=headers,
            content_type=headers.get("content-type"),
            body_preview=body_preview,
            response_size_bytes=response_size,
            response_time_ms=elapsed_ms,
            path_category=category,
            path=path,
        )

    except httpx.TooManyRedirects:
        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)
        return ProbeResult(
            requested_url=url,
            final_url=url,
            error="TooManyRedirects",
            response_time_ms=elapsed_ms,
            path_category=category,
            path=path,
        )
    except httpx.TimeoutException as exc:
        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)
        return ProbeResult(
            requested_url=url,
            final_url=url,
            error=f"Timeout({type(exc).__name__})",
            response_time_ms=elapsed_ms,
            path_category=category,
            path=path,
        )
    except httpx.ConnectError as exc:
        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)
        return ProbeResult(
            requested_url=url,
            final_url=url,
            error=f"ConnectError: {exc}",
            response_time_ms=elapsed_ms,
            path_category=category,
            path=path,
        )
    except httpx.InvalidURL as exc:
        return ProbeResult(
            requested_url=url,
            final_url=url,
            error=f"InvalidURL: {exc}",
            path_category=category,
            path=path,
        )
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)
        logger.debug("Unexpected error probing %s: %s", url, exc, exc_info=True)
        return ProbeResult(
            requested_url=url,
            final_url=url,
            error=f"{type(exc).__name__}: {exc}",
            response_time_ms=elapsed_ms,
            path_category=category,
            path=path,
        )


@with_http_retry()
async def _probe_graphql_introspection(
    client: httpx.AsyncClient,
    domain: str,
    path: str,
    scheme: str,
) -> ProbeResult | None:
    """
    Issue a GraphQL introspection POST to detect open introspection endpoints.

    Called only when a GET to the same path returned a non-error status.
    Returns None if the POST itself fails with a network error.
    """
    url = build_probe_url(domain, path, scheme)
    t_start = time.monotonic()

    try:
        response = await client.post(
            url,
            content=_GRAPHQL_INTROSPECTION.encode(),
            headers={"Content-Type": "application/json"},
        )
        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)

        raw_body = response.content
        body_preview = raw_body[: settings.body_preview_bytes].decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Tag this as an introspection probe with a synthetic path suffix
        return ProbeResult(
            requested_url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            response_headers=headers,
            content_type=headers.get("content-type"),
            body_preview=body_preview,
            response_size_bytes=len(raw_body),
            response_time_ms=elapsed_ms,
            path_category="graphql_introspection",
            path=path + "[introspection_post]",
        )
    except Exception as exc:
        logger.debug("GraphQL introspection POST failed for %s%s: %s", domain, path, exc)
        return None


# ---------------------------------------------------------------------------
# Domain-level probe
# ---------------------------------------------------------------------------


async def probe_domain(domain: Domain, client: httpx.AsyncClient) -> ProbeSet:
    """
    Probe a single domain across all configured paths.

    Args:
        domain: The ``Domain`` object to probe.
        client: A shared httpx async client.

    Returns:
        A ``ProbeSet`` containing one ``ProbeResult`` per probed path.
    """
    logger.debug("Probing domain: %s (%s)", domain.hostname, domain.probe_scheme)
    probe_results: list[ProbeResult] = []

    for path in get_all_paths():
        result = await _probe_one(client, domain.hostname, path, domain.probe_scheme)
        probe_results.append(result)

        # Issue GraphQL introspection POST if GET succeeded on a GraphQL path
        if is_graphql_path(path) and result.is_successful and result.status_code not in (404, 405):
            introspection = await _probe_graphql_introspection(
                client, domain.hostname, path, domain.probe_scheme
            )
            if introspection is not None:
                probe_results.append(introspection)

    probe_set = ProbeSet(
        domain=domain.hostname,
        probed_at=datetime.now(timezone.utc),
        probes=probe_results,
    )

    success = probe_set.success_count
    total = probe_set.probe_count
    logger.info("  %-45s  %d/%d paths OK", domain.hostname, success, total)

    return probe_set


# ---------------------------------------------------------------------------
# Pipeline-level: probe all domains with concurrency limiting
# ---------------------------------------------------------------------------


async def probe_all(domains: list[Domain]) -> list[ProbeSet]:
    """
    Probe all domains concurrently, bounded by ``config.prober_concurrency``.

    A single ``httpx.AsyncClient`` is shared across all domain probes for
    efficient connection pooling.  A semaphore limits concurrent domains.

    Args:
        domains: List of normalised ``Domain`` objects from the loader.

    Returns:
        A list of ``ProbeSet`` objects in the same order as ``domains``.
    """
    if not domains:
        return []

    semaphore = asyncio.Semaphore(settings.prober_concurrency)
    results: list[ProbeSet] = []

    async with _make_client() as client:

        async def _bounded_probe(domain: Domain) -> ProbeSet:
            async with semaphore:
                return await probe_domain(domain, client)

        logger.info(
            "Starting Tier 1 probing: %d domain(s), concurrency=%d",
            len(domains),
            settings.prober_concurrency,
        )
        results = list(
            await asyncio.gather(*(_bounded_probe(d) for d in domains))
        )

    logger.info("Tier 1 probing complete: %d probe sets", len(results))
    return results
