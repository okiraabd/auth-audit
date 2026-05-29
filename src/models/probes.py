"""
models/probes.py — Raw HTTP probe result models for Tier 1.

``ProbeResult`` holds everything captured from a single HTTP request to a
single path on a domain.  ``ProbeSet`` groups all probe results for one domain.

These are the *raw data* models — no signals, no verdicts, no scoring.
Signal extraction happens in ``tier1.signal_extractor``.

Key design decisions:
  - ``body_preview`` is truncated to ``config.body_preview_bytes`` by the
    prober; the full body is never stored in memory.
  - ``redirect_chain`` includes the initial URL + every intermediate URL,
    *excluding* the final URL (which is stored in ``final_url``).
  - ``error`` is a plain string (not an exception) so it survives
    serialisation to JSON.
  - ``path_category`` is stamped by the prober using ``prober.path_strategy``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from pydantic import BaseModel, Field, computed_field


# ---------------------------------------------------------------------------
# Single probe result
# ---------------------------------------------------------------------------


class ProbeResult(BaseModel):
    """
    The complete capture from one HTTP probe request.

    Created by ``prober.http_prober`` for each (domain, path) pair.
    """

    # URL tracking
    requested_url: str = Field(description="The URL sent to httpx (before any redirects).")
    final_url: str = Field(description="The URL actually responded to (after all redirects).")
    redirect_chain: list[str] = Field(
        default_factory=list,
        description="Ordered list of intermediate URLs followed during redirects.",
    )

    # Response basics
    status_code: int | None = Field(
        default=None,
        description="HTTP status code. None if a network/TLS error prevented a response.",
    )
    response_headers: dict[str, str] = Field(
        default_factory=dict,
        description="All response headers, lowercased keys.",
    )
    content_type: str | None = Field(
        default=None,
        description="Value of the Content-Type header (convenience extraction).",
    )

    # Body / size
    body_preview: str = Field(
        default="",
        description="Truncated body text (up to config.body_preview_bytes).",
    )
    response_size_bytes: int = Field(
        default=0,
        ge=0,
        description="Total response body size in bytes (from Content-Length or actual read).",
    )

    # Timing & errors
    response_time_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Time in milliseconds from request send to response headers received.",
    )
    error: str | None = Field(
        default=None,
        description="Network or TLS error message. None if the request succeeded.",
    )

    # Metadata stamped by the prober
    path_category: str = Field(
        default="unknown",
        description="Path category: 'web' | 'api' | 'docs' | 'graphql' | 'unknown'.",
    )
    path: str = Field(
        default="/",
        description="The path component probed (e.g. '/api/v1').",
    )

    # -------------------------------------------------------------------------
    # Computed helpers
    # -------------------------------------------------------------------------

    @computed_field  # type: ignore[misc]
    @property
    def is_successful(self) -> bool:
        """True when we received an HTTP response (error-free)."""
        return self.status_code is not None and self.error is None

    @computed_field  # type: ignore[misc]
    @property
    def is_redirect(self) -> bool:
        """True when the final status code is a redirect."""
        return self.status_code in {301, 302, 303, 307, 308}

    @computed_field  # type: ignore[misc]
    @property
    def is_json_response(self) -> bool:
        """True when the Content-Type indicates a JSON body."""
        ct = (self.content_type or "").lower()
        return "application/json" in ct or "application/ld+json" in ct

    @computed_field  # type: ignore[misc]
    @property
    def is_html_response(self) -> bool:
        """True when the Content-Type indicates an HTML body."""
        return "text/html" in (self.content_type or "").lower()

    @computed_field  # type: ignore[misc]
    @property
    def redirect_count(self) -> int:
        """Number of redirects followed."""
        return len(self.redirect_chain)

    @computed_field  # type: ignore[misc]
    @property
    def www_authenticate(self) -> str | None:
        """Value of the WWW-Authenticate header, if present."""
        return self.response_headers.get("www-authenticate")


# ---------------------------------------------------------------------------
# Probe set — all probes for one domain
# ---------------------------------------------------------------------------


class ProbeSet(BaseModel):
    """
    All HTTP probe results for a single domain, across every path probed.

    Created by ``prober.http_prober.probe_domain``.
    """

    domain: str = Field(description="The FQDN that was probed.")
    probed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when probing started for this domain.",
    )
    probes: list[ProbeResult] = Field(
        default_factory=list,
        description="All probe results, in the order paths were attempted.",
    )

    # -------------------------------------------------------------------------
    # Accessors
    # -------------------------------------------------------------------------

    def get_probe(self, path: str) -> ProbeResult | None:
        """Return the ProbeResult for a specific path, or None if not probed."""
        for p in self.probes:
            if p.path == path:
                return p
        return None

    def get_root_probe(self) -> ProbeResult | None:
        """Return the ProbeResult for the root path '/', or the first probe."""
        root = self.get_probe("/")
        return root if root is not None else (self.probes[0] if self.probes else None)

    def successful_probes(self) -> list[ProbeResult]:
        """Return only probes that received an HTTP response."""
        return [p for p in self.probes if p.is_successful]

    def failed_probes(self) -> list[ProbeResult]:
        """Return only probes that encountered a network error."""
        return [p for p in self.probes if p.error is not None]

    def probes_by_category(self, category: str) -> list[ProbeResult]:
        """Return all probes belonging to a given path_category."""
        return [p for p in self.probes if p.path_category == category]

    @property
    def all_unreachable(self) -> bool:
        """True when every probe failed with a network error."""
        return bool(self.probes) and all(p.error is not None for p in self.probes)

    @property
    def probe_count(self) -> int:
        return len(self.probes)

    @property
    def success_count(self) -> int:
        return len(self.successful_probes())

    def compact_summary(self) -> dict:
        """
        Return a compact dict summarising all probes — used in DomainResult.probe_summary.

        Shape: { "/path": {"status": 200, "category": "web", "error": null, ...} }
        """
        return {
            p.path: {
                "status": p.status_code,
                "final_url": p.final_url,
                "content_type": p.content_type,
                "redirect_count": p.redirect_count,
                "response_time_ms": round(p.response_time_ms, 1),
                "error": p.error,
                "category": p.path_category,
            }
            for p in self.probes
        }
