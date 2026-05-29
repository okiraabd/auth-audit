"""
discovery/route_discoverer.py — Phase 0 API route discovery for auth-audit.

Runs **before** Tier 1 rule evaluation.  When a domain returns a very high
proportion of 404s on the initial probe set, this module probes a large
curated wordlist (or calls kiterunner if available) to find real routes that
may expose authentication signals (401, 403, live JSON, login forms, etc.).

Discovered paths are merged back into the existing ProbeSet before Tier 1
analyses signals, dramatically reducing UNKNOWN verdicts for API domains.

Strategy
--------
1. Check if all (or most) initial probes returned 404 (all_404 detection).
2. If yes and Active Discovery is enabled, probe the built-in wordlist — excluding paths
   already tested in Phase 1.
3. Keep only paths that returned a non-404, non-error response (viable signal).
4. Optionally invoke kiterunner binary if available and enabled in config.
5. Merge all discovered ``ProbeResult``s into the existing ``ProbeSet``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx

from config import settings
from models.domain import Domain
from models.probes import ProbeResult, ProbeSet
from discovery.wordlist import BUILTIN_API_PATHS
from prober.path_strategy import classify_path
from utils.urls import build_probe_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Trigger condition
# ---------------------------------------------------------------------------

_ALL_404_CATEGORY = {"404", "unknown", "not_found"}


def should_trigger(probe_set: ProbeSet) -> bool:
    """
    Return True when Phase 0 discovery is worthwhile.

    Triggers when >= discovery_trigger_404_ratio of successful probes are 404.
    The service must be reachable (at least some probes succeeded) for
    discovery to make sense.
    """
    if not settings.discovery_enabled:
        return False

    successful = probe_set.successful_probes()
    if len(successful) < 3:
        # Too few probes to judge — skip (likely unreachable or all network errors)
        return False

    not_found_count = sum(1 for p in successful if p.status_code == 404)
    ratio = not_found_count / len(successful)
    return ratio >= settings.discovery_trigger_404_ratio


# ---------------------------------------------------------------------------
# Wordlist-based discovery
# ---------------------------------------------------------------------------


async def _probe_one_path(
    client: httpx.AsyncClient,
    domain: str,
    path: str,
    scheme: str,
) -> ProbeResult | None:
    """
    Probe a single path, returning None on network error.
    Only keeps non-404 responses — 404s are noise here.
    """
    import time
    import warnings

    url = build_probe_url(domain, path, scheme)
    t_start = time.monotonic()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = await client.get(url)
        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)

        # Skip 404 — we're looking for paths with real responses
        if response.status_code == 404:
            return None

        headers = {k.lower(): v for k, v in response.headers.items()}
        raw_body = response.content
        body_preview = raw_body[: settings.body_preview_bytes].decode("utf-8", errors="replace")

        return ProbeResult(
            requested_url=url,
            final_url=str(response.url),
            redirect_chain=[str(r.url) for r in response.history],
            status_code=response.status_code,
            response_headers=headers,
            content_type=headers.get("content-type"),
            body_preview=body_preview,
            response_size_bytes=len(raw_body),
            response_time_ms=elapsed_ms,
            path_category="discovery_discovered",  # distinct badge in HTML report
            path=path,
        )
    except Exception:
        return None


async def _discover_via_wordlist(
    domain: Domain,
    existing_paths: set[str],
) -> list[ProbeResult]:
    """
    Probe every path in BUILTIN_API_PATHS that was not already tested.
    Returns only non-404, non-error responses.
    """
    candidates = [p for p in BUILTIN_API_PATHS if p not in existing_paths]
    if not candidates:
        return []

    logger.info("[Discovery] Wordlist scan: %s (%d new paths)", domain.hostname, len(candidates))

    discovered: list[ProbeResult] = []
    sem = asyncio.Semaphore(settings.prober_concurrency)

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            follow_redirects=True,
            max_redirects=settings.http_max_redirects,
            verify=False,
            headers={"User-Agent": settings.http_user_agent},
        ) as client:

            async def _bounded(path: str) -> None:
                async with sem:
                    result = await _probe_one_path(client, domain.hostname, path, domain.probe_scheme)
                    if result is not None:
                        discovered.append(result)

            await asyncio.gather(*(_bounded(p) for p in candidates))

    logger.info(
        "[Discovery] Wordlist scan complete: %s — %d/%d paths with viable responses",
        domain.hostname,
        len(discovered),
        len(candidates),
    )
    return discovered


# ---------------------------------------------------------------------------
# Kiterunner-based discovery (optional)
# ---------------------------------------------------------------------------


def _kiterunner_available() -> bool:
    """Return True if the 'kr' binary is on PATH."""
    return shutil.which(settings.kiterunner_binary) is not None


def _discover_via_kiterunner(domain: Domain) -> list[str]:
    """
    Run kiterunner and return a list of discovered paths.
    Returns empty list if kiterunner is unavailable or fails.
    """
    if not _kiterunner_available():
        return []

    target = f"{domain.probe_scheme}://{domain.hostname}"
    wordlist = settings.kiterunner_wordlist or "routes.kite"

    logger.info("[Discovery] kiterunner scan: %s", target)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name

    try:
        cmd = [
            settings.kiterunner_binary,
            "scan",
            target,
            "-w", str(wordlist),
            "-x", str(settings.kiterunner_concurrency),
            "--ignore-length", "0",
            "--quiet",
            "-o", "json",
            "--output-file", out_path,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.kiterunner_timeout,
        )
        if result.returncode != 0:
            logger.warning("[Discovery] kiterunner exited %d: %s", result.returncode, result.stderr[:200])
            return []

        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
        # kiterunner JSON output: list of {path: ..., status: ..., ...}
        return [item["path"] for item in data if isinstance(item, dict) and "path" in item]

    except subprocess.TimeoutExpired:
        logger.warning("[Discovery] kiterunner timed out for %s", domain.hostname)
        return []
    except Exception as exc:
        logger.warning("[Discovery] kiterunner error for %s: %s", domain.hostname, exc)
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def discover_and_merge(
    domain: Domain, probe_set: ProbeSet
) -> tuple[ProbeSet, dict | None]:
    """
    Run Phase 0 discovery and return an updated ProbeSet with discovered paths,
    plus a discovery_output metadata dict (or None if not triggered).

    If the trigger condition is not met (not all-404), returns the original
    ProbeSet unchanged with None metadata.

    Args:
        domain:    The domain being audited.
        probe_set: The ProbeSet from Phase 1 probing.

    Returns:
        A tuple of (ProbeSet, discovery_output | None).
    """
    if not should_trigger(probe_set):
        return probe_set, None

    logger.info(
        "[Discovery] Triggering API route discovery for %s (high 404 ratio on initial probes)",
        domain.hostname,
    )

    existing_paths = {p.path for p in probe_set.probes}
    discovered: list[ProbeResult] = []
    methods_used: list[str] = []

    # --- kiterunner (optional) ---
    if settings.kiterunner_enabled and _kiterunner_available():
        kr_paths = _discover_via_kiterunner(domain)
        new_kr_paths = [p for p in kr_paths if p not in existing_paths]
        if new_kr_paths:
            discovered += await _discover_via_wordlist_paths(domain, new_kr_paths, existing_paths)
            methods_used.append("kiterunner")

    # --- Built-in wordlist ---
    wordlist_results = await _discover_via_wordlist(domain, existing_paths)
    discovered.extend(wordlist_results)
    if wordlist_results:
        methods_used.append("wordlist")

    discovery_meta: dict = {
        "triggered": True,
        "paths_found": len(discovered),
        "methods_used": methods_used if methods_used else ["wordlist"],
        "discovered_paths": [r.path for r in discovered],
    }

    if not discovered:
        logger.info("[Discovery] No new viable paths found for %s", domain.hostname)
        discovery_meta["paths_found"] = 0
        return probe_set, discovery_meta

    logger.info("[Discovery] Merging %d discovered paths into ProbeSet for %s", len(discovered), domain.hostname)
    new_probe_set = ProbeSet(
        domain=probe_set.domain,
        probed_at=probe_set.probed_at,
        probes=probe_set.probes + discovered,
    )
    return new_probe_set, discovery_meta


async def _discover_via_wordlist_paths(
    domain: Domain,
    paths: list[str],
    existing_paths: set[str],
) -> list[ProbeResult]:
    """Probe a specific list of paths (used by kiterunner-discovered paths)."""
    candidates = [p for p in paths if p not in existing_paths]
    if not candidates:
        return []

    discovered: list[ProbeResult] = []
    sem = asyncio.Semaphore(settings.prober_concurrency)

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            follow_redirects=True,
            max_redirects=settings.http_max_redirects,
            verify=False,
            headers={"User-Agent": settings.http_user_agent},
        ) as client:

            async def _bounded(path: str) -> None:
                async with sem:
                    result = await _probe_one_path(client, domain.hostname, path, domain.probe_scheme)
                    if result is not None:
                        discovered.append(result)

            await asyncio.gather(*(_bounded(p) for p in candidates))

    return discovered
