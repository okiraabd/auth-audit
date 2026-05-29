"""
models/result.py — Final per-domain audit result schema.

``DomainResult`` is the **stable output contract** for the entire pipeline.
Every tier writes into this schema — the orchestrator merges partial tier
outputs into a single ``DomainResult`` per domain.

Verdict semantics:
  PROTECTED        — Strong auth signals; high confidence access is gated.
  PARTIAL          — Mixed signals; some paths protected, others not.
  OPEN             — No auth; clearly public content, no risk signals.
  OPEN_API         — REST API reachable without auth (data unclear).
  OPEN_API_CRITICAL — REST API returning real / sensitive data without auth.
  OPEN_DOCS        — Swagger/OpenAPI/Redoc docs exposed without auth.
  GRAPHQL_OPEN     — GraphQL endpoint reachable; introspection unknown.
  GRAPHQL_CRITICAL — GraphQL introspection / schema fully exposed.
  UNREACHABLE      — Domain could not be reached on any probed path.
  UNKNOWN          — Insufficient evidence for any verdict.

Service type semantics:
  WEB_APP   — Primarily HTML UI.
  REST_API  — Primarily JSON REST API.
  GRAPHQL   — GraphQL endpoint.
  MIXED     — Combination (e.g. HTML root + JSON /api/*).
  UNKNOWN   — Could not be determined.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ServiceType(str, Enum):
    """Detected service type for a domain."""

    WEB_APP = "WEB_APP"
    REST_API = "REST_API"
    GRAPHQL = "GRAPHQL"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"


class Verdict(str, Enum):
    """
    Final authentication / exposure verdict for a domain.

    String-valued so instances serialise to plain strings in JSON output.
    """

    PROTECTED = "PROTECTED"
    PARTIAL = "PARTIAL"
    OPEN = "OPEN"
    OPEN_API = "OPEN_API"
    OPEN_API_CRITICAL = "OPEN_API_CRITICAL"
    OPEN_DOCS = "OPEN_DOCS"
    GRAPHQL_OPEN = "GRAPHQL_OPEN"
    GRAPHQL_CRITICAL = "GRAPHQL_CRITICAL"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "Verdict":
        """Gracefully fall back to UNKNOWN for unrecognised strings."""
        return cls.UNKNOWN


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class DomainResult(BaseModel):
    """
    Canonical per-domain output.  Produced after all applicable tiers run.

    Fields must remain stable across all tiers and the JSON report format.
    """

    domain: str = Field(description="The audited FQDN.")

    service_type: ServiceType = Field(
        default=ServiceType.UNKNOWN,
        description="Detected service type (web app, API, GraphQL, mixed).",
    )
    final_verdict: Verdict = Field(
        default=Verdict.UNKNOWN,
        description="Authentication / exposure verdict.",
    )
    confidence: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Pipeline confidence in the verdict (0–100).",
    )
    tier_reached: int = Field(
        default=1,
        ge=1,
        le=3,
        description="The highest tier that contributed to the final verdict.",
    )
    signals: list[str] = Field(
        default_factory=list,
        description="Human-readable labels for all signals detected (e.g. 'R_BEARER_CHALLENGE').",
    )
    reasoning: str = Field(
        default="",
        description="Free-text explanation of the verdict, aggregated across tiers.",
    )
    needs_manual_review: bool = Field(
        default=False,
        description="True when the pipeline could not reach a confident verdict.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Supporting evidence items (URLs, excerpts, screenshot paths).",
    )
    probe_summary: dict = Field(
        default_factory=dict,
        description="Compact summary of Tier 1 probe results keyed by path.",
    )

    # Optional per-tier detail blobs — populated when that tier ran
    discovery_output: dict | None = Field(
        default=None,
        description="Route discovery output dict from Active Discovery (if triggered).",
    )
    tier1_output: dict | None = Field(
        default=None,
        description="Rule engine output dict from Tier 1.",
    )
    tier2_output: dict | None = Field(
        default=None,
        description="LLM analyzer output dict from Tier 2 (if reached).",
    )
    tier3_output: dict | None = Field(
        default=None,
        description="Browser escalation output dict from Tier 3 (if reached).",
    )

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, v: int) -> int:
        return max(0, min(100, v))

    # -------------------------------------------------------------------------
    # Convenience helpers
    # -------------------------------------------------------------------------

    @property
    def is_critical(self) -> bool:
        """Return True for verdicts that indicate a severe exposure."""
        return self.final_verdict in {
            Verdict.OPEN_API_CRITICAL,
            Verdict.GRAPHQL_CRITICAL,
        }

    @property
    def is_open(self) -> bool:
        """Return True for any open / unprotected verdict."""
        return self.final_verdict in {
            Verdict.OPEN,
            Verdict.OPEN_API,
            Verdict.OPEN_API_CRITICAL,
            Verdict.OPEN_DOCS,
            Verdict.GRAPHQL_OPEN,
            Verdict.GRAPHQL_CRITICAL,
        }

    def model_post_init(self, __context: object) -> None:
        """Auto-set needs_manual_review for unknown / partial / broken verdicts."""
        flag = False

        # Low-confidence unknown or partial
        if self.final_verdict in {Verdict.UNKNOWN, Verdict.PARTIAL} and self.confidence < 50:
            flag = True

        # All-404 broken service detected by Tier 1
        t1 = self.tier1_output or {}
        if "no matching routes" in (t1.get("ambiguity_reason") or "").lower():
            flag = True

        # Tier 3 parse failure — couldn't get browser verdict
        t3 = self.tier3_output or {}
        if t3.get("_parse_error") or t3.get("_error"):
            if self.final_verdict == Verdict.UNKNOWN:
                flag = True

        if flag:
            object.__setattr__(self, "needs_manual_review", True)
