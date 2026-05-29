"""
loaders/proxy_host_loader.py — Proxy host JSON file loader and domain extractor.

Reads a JSON file containing proxy host entries and normalises them into a
deduplicated, ordered list of ``Domain`` objects ready for Tier 1 probing.

Supported JSON shapes
---------------------
Shape 1 — Nginx Proxy Manager (NPM) export (primary target):

    [
      {
        "id": 3,
        "domain_names": ["example.internal"],
        "forward_scheme": "http",
        "ssl_forced": true,
        "enabled": true,
        ...
      }
    ]

Shape 2 — Simple list with a single "domain" key:

    [{"domain": "example.internal", "enabled": true}]

Shape 3 — Simple list with a "host" key:

    [{"host": "example.internal"}]

All shapes are auto-detected. Unknown shapes that yield no domain are logged
and skipped — they never raise an exception.

Normalisation rules
-------------------
- ``enabled == false`` entries are skipped (entry without the flag: included).
- Domains are extracted from ``domain_names`` (list), ``domain``, or ``host``.
- Each raw value is passed through ``utils.urls.normalise_domain``.
- Domains are deduplicated (case-insensitive); first occurrence wins.
- Invalid / unparseable entries are logged at WARNING level and skipped.

Probe scheme inference
----------------------
- ``ssl_forced == true``          → scheme = "https"
- ``forward_scheme == "https"``   → scheme = "https"
- No flag present                 → scheme = "https" (safe default)
- Both flags absent or false      → scheme = "http"
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Literal

from models.domain import Domain
from utils.urls import normalise_domain

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_domains(path: str | Path) -> list[Domain]:
    """
    Load and normalise proxy host entries from a JSON file.

    Args:
        path: Path to the proxy host JSON file.

    Returns:
        A deduplicated, ordered list of ``Domain`` objects.
        Domains preserve the order of first occurrence in the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError:        If the file content is not valid JSON, or if the
                           top-level JSON value is not a list.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Proxy host file not found: {path}")

    logger.info("Loading proxy hosts from %s", path)

    raw_text = path.read_text(encoding="utf-8")

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, list):
        raise ValueError(
            f"Expected a JSON array at the top level of {path}, "
            f"got {type(data).__name__}."
        )

    domains = _parse_entries(data)

    logger.info(
        "Loaded %d unique domain(s) from %d raw entries (file: %s)",
        len(domains),
        len(data),
        path.name,
    )
    return domains


# ---------------------------------------------------------------------------
# Internal parsing helpers
# ---------------------------------------------------------------------------


def _parse_entries(entries: list) -> list[Domain]:
    """
    Parse a list of raw proxy host dicts into deduplicated Domain objects.

    Processing order:
      1. Filter disabled entries.
      2. Extract raw domain name strings.
      3. Normalise each domain string.
      4. Deduplicate by lowercase hostname.
      5. Construct Domain objects.
    """
    seen: dict[str, Domain] = {}  # hostname → Domain (preserves insertion order)
    skipped_invalid = 0
    skipped_disabled = 0

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            logger.warning(
                "Entry #%d is not a dict (got %s) — skipping.",
                index,
                type(entry).__name__,
            )
            skipped_invalid += 1
            continue

        # Skip disabled entries
        if not _is_enabled(entry):
            logger.debug("Entry #%d (id=%s) is disabled — skipping.", index, entry.get("id", "?"))
            skipped_disabled += 1
            continue

        raw_names = _extract_raw_domain_names(entry)
        if not raw_names:
            logger.warning(
                "Entry #%d (id=%s) has no extractable domain name — skipping.",
                index,
                entry.get("id", "?"),
            )
            skipped_invalid += 1
            continue

        scheme = _infer_probe_scheme(entry)

        for raw_name in raw_names:
            try:
                hostname = normalise_domain(raw_name)
            except ValueError as exc:
                logger.warning(
                    "Entry #%d — cannot normalise domain %r: %s — skipping this name.",
                    index,
                    raw_name,
                    exc,
                )
                skipped_invalid += 1
                continue

            if not hostname:
                continue

            if hostname in seen:
                logger.debug("Domain %r already seen — skipping duplicate.", hostname)
                continue

            domain = Domain(
                hostname=hostname,
                probe_scheme=scheme,
                source_id=_extract_source_id(entry),
                raw_entry=entry,
            )
            seen[hostname] = domain

    if skipped_disabled:
        logger.info("Skipped %d disabled proxy host entry/entries.", skipped_disabled)
    if skipped_invalid:
        logger.warning("Skipped %d invalid/unparseable entry/entries.", skipped_invalid)

    return list(seen.values())


def _is_enabled(entry: dict) -> bool:
    """
    Return True if the entry should be audited.

    An entry is considered enabled when:
      - The ``enabled`` key is absent (no flag → include by default).
      - The ``enabled`` key is present and truthy.
    """
    enabled = entry.get("enabled")
    if enabled is None:
        return True
    return bool(enabled)


def _extract_raw_domain_names(entry: dict) -> list[str]:
    """
    Extract raw (un-normalised) domain name strings from a proxy host entry.

    Tries multiple field names in priority order to handle different JSON shapes.
    Returns an empty list if no domain names are found.
    """
    # Shape 1 — NPM: domain_names is a list (or occasionally a string)
    if "domain_names" in entry:
        raw = entry["domain_names"]
        if isinstance(raw, list):
            return [str(d).strip() for d in raw if str(d).strip()]
        if isinstance(raw, str) and raw.strip():
            return [raw.strip()]

    # Shape 2 — single "domain" string field
    if "domain" in entry:
        raw = entry["domain"]
        if isinstance(raw, str) and raw.strip():
            return [raw.strip()]

    # Shape 3 — single "host" string field
    if "host" in entry:
        raw = entry["host"]
        if isinstance(raw, str) and raw.strip():
            return [raw.strip()]

    return []


def _infer_probe_scheme(entry: dict) -> Literal["https", "http"]:
    """
    Infer the probe scheme from the proxy host entry's TLS flags.

    Priority:
      1. ``ssl_forced == true``       → "https"
      2. ``forward_scheme == "https"``→ "https"
      3. Default                      → "https" (safe default for public services)
    """
    if entry.get("ssl_forced") is True:
        return "https"
    if entry.get("forward_scheme", "").lower() == "https":
        return "https"
    # If ssl_forced is explicitly False AND forward_scheme is http, use http
    if entry.get("ssl_forced") is False and entry.get("forward_scheme", "").lower() == "http":
        return "http"
    return "https"


def _extract_source_id(entry: dict) -> int | None:
    """Return the proxy host's integer ID, or None if not present."""
    raw_id = entry.get("id")
    if isinstance(raw_id, int):
        return raw_id
    if isinstance(raw_id, str) and raw_id.isdigit():
        return int(raw_id)
    return None
