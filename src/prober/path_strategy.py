"""
prober/path_strategy.py — Probe path definitions and selection logic.

Defines the canonical path sets probed per domain during Tier 1, and
provides pure helper functions for path category classification.

All data and functions in this module are pure — no I/O, no config reads
at import time (custom path overrides are loaded lazily on first call).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Canonical path sets — as specified in the architecture brief (§10)
# ---------------------------------------------------------------------------

WEB_PATHS: list[str] = [
    "/",
    "/login",
    "/signin",
    "/auth",
    "/admin",
    "/dashboard",
]

API_PATHS: list[str] = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/rest",
]

DOC_PATHS: list[str] = [
    "/swagger",
    "/swagger-ui",
    "/openapi.json",
    "/api-docs",
    "/redoc",
]

GRAPHQL_PATHS: list[str] = [
    "/graphql",
    "/gql",
    "/api/graphql",
]

# Ordered by detection priority (web first — root path is highest signal)
_DEFAULT_ORDER: list[str] = WEB_PATHS + API_PATHS + DOC_PATHS + GRAPHQL_PATHS

# Reverse-lookup: path → category
_PATH_CATEGORY: dict[str, str] = {}
for _p in WEB_PATHS:
    _PATH_CATEGORY[_p] = "web"
for _p in API_PATHS:
    _PATH_CATEGORY[_p] = "api"
for _p in DOC_PATHS:
    _PATH_CATEGORY[_p] = "docs"
for _p in GRAPHQL_PATHS:
    _PATH_CATEGORY[_p] = "graphql"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_all_paths() -> list[str]:
    """
    Return the full ordered list of paths to probe per domain.

    Web paths come first because the root path (``/``) and ``/login`` are
    the highest-signal starting points for auth detection.

    Deduplication preserves first-occurrence order.
    """
    seen: set[str] = set()
    result: list[str] = []
    for path in _DEFAULT_ORDER:
        if path not in seen:
            result.append(path)
            seen.add(path)
    return result


def classify_path(path: str) -> str:
    """
    Return the category label for a probe path.

    Returns one of: ``'web'`` | ``'api'`` | ``'docs'`` | ``'graphql'`` | ``'unknown'``

    Uses an exact match first, then checks if the path *starts with* a known
    prefix to handle parameterised paths like ``/api/v1/users``.

    >>> classify_path("/")
    'web'
    >>> classify_path("/api/v1")
    'api'
    >>> classify_path("/graphql")
    'graphql'
    >>> classify_path("/swagger")
    'docs'
    >>> classify_path("/unknown-path")
    'unknown'
    """
    # Exact match
    if path in _PATH_CATEGORY:
        return _PATH_CATEGORY[path]

    # Prefix match (handles paths like /api/v1/users, /admin/settings)
    for known_path, category in _PATH_CATEGORY.items():
        if known_path != "/" and path.startswith(known_path + "/"):
            return category

    return "unknown"


def is_graphql_path(path: str) -> bool:
    """Return True if the path is a known GraphQL endpoint path."""
    return classify_path(path) == "graphql"


def is_docs_path(path: str) -> bool:
    """Return True if the path is a known API documentation path."""
    return classify_path(path) == "docs"
