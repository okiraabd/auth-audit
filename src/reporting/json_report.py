"""
reporting/json_report.py — JSON output writer for audit results.

Serializes the final list of DomainResult objects to a well-formed JSON file
using orjson for fast, spec-compliant serialization.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import orjson

from models.result import DomainResult

logger = logging.getLogger(__name__)


def write_json_report(results: list[DomainResult], output_path: Path) -> None:
    """
    Serialize ``results`` to a JSON file at ``output_path``.

    The output JSON has the shape:
    {
        "generated_at": "<ISO-8601 UTC>",
        "total": <int>,
        "summary": { "<verdict>": <count>, ... },
        "results": [ <DomainResult>, ... ]
    }

    Args:
        results:     List of DomainResult objects.
        output_path: Destination file path (created if missing).
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Build per-verdict summary counts
    summary: dict[str, int] = {}
    for r in results:
        verdict = r.final_verdict.value
        summary[verdict] = summary.get(verdict, 0) + 1

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "summary": summary,
        "results": [_serialise_result(r) for r in results],
    }

    data = orjson.dumps(payload, option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS)
    output_path.write_bytes(data)

    logger.info("JSON report written to %s (%d domains)", output_path, len(results))


# Private keys produced by LLM analyzers for debugging — excluded from reports
_PRIVATE_KEYS = frozenset({"_raw_response", "_error", "_parse_error"})


def _serialise_result(result: DomainResult) -> dict:
    """
    Dump a DomainResult to a JSON-safe dict, stripping internal debug fields
    (_raw_response, _error, _parse_error) from tier2_output and tier3_output.
    """
    data = result.model_dump(mode="json")

    for tier_key in ("tier2_output", "tier3_output"):
        tier = data.get(tier_key)
        if isinstance(tier, dict):
            for key in _PRIVATE_KEYS:
                tier.pop(key, None)

    return data
