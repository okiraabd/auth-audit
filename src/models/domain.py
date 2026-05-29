"""
models/domain.py — Domain data model.

Represents a single, normalised domain entry extracted from the proxy host
JSON input and ready to be probed by the Tier 1 HTTP prober.

Design notes:
  - ``hostname`` is always a clean FQDN (no scheme, no port, lowercase).
  - ``probe_scheme`` is inferred from ``ssl_forced`` in NPM JSON; it tells
    the prober which scheme to use when building probe URLs.
  - ``source_id`` preserves the originating proxy host's ID for traceability.
  - ``raw_entry`` stores the full original dict so downstream code can access
    NPM-specific fields (e.g. ``forward_host``, ``certificate_id``) if needed.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator


class Domain(BaseModel):
    """
    A single normalised domain ready to be probed.

    Created by ``loaders.proxy_host_loader.load_domains``.
    """

    hostname: Annotated[str, Field(min_length=1, description="Clean FQDN, lowercase, no scheme or port.")]
    """e.g. ``example.internal`` or ``api.service.company.com``"""

    probe_scheme: Literal["https", "http"] = Field(
        default="https",
        description=(
            "Protocol to use when building probe URLs. "
            "Derived from ssl_forced=true (NPM) → 'https'; otherwise 'http'."
        ),
    )

    source_id: int | None = Field(
        default=None,
        description="ID of the originating proxy host entry (e.g. NPM proxy host id).",
    )

    raw_entry: dict = Field(
        default_factory=dict,
        description="The original, unmodified proxy host JSON entry for traceability.",
        exclude=False,
    )

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------

    @field_validator("hostname")
    @classmethod
    def _clean_hostname(cls, v: str) -> str:
        """Lowercase and strip any residual whitespace."""
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("hostname must not be empty after stripping")
        # Reject anything that still looks like it has a scheme
        if "://" in cleaned:
            raise ValueError(
                f"hostname must not contain a scheme, got {v!r}. "
                "Use utils.urls.normalise_domain() before constructing Domain."
            )
        return cleaned

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def probe_base_url(self) -> str:
        """Return the base URL for probing: ``https://hostname``."""
        return f"{self.probe_scheme}://{self.hostname}"

    # -------------------------------------------------------------------------
    # Dunder helpers
    # -------------------------------------------------------------------------

    def __str__(self) -> str:
        return self.hostname

    def __repr__(self) -> str:
        return f"Domain(hostname={self.hostname!r}, scheme={self.probe_scheme!r})"

    def __hash__(self) -> int:
        return hash(self.hostname)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Domain):
            return self.hostname == other.hostname
        return NotImplemented

    model_config = {"frozen": False}
