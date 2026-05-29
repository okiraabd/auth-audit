"""
reporting/json_writer.py — Serialises pipeline results to a JSON output file.

Responsibilities:
  - Accept the final list of ``DomainResult`` objects
  - Serialise to JSON using ``orjson`` for speed and datetime support
  - Write to ``config.results_json`` (creating parent directories as needed)
  - Include a run metadata envelope (timestamp, domain count, verdict distribution)
  - Support streaming write for large domain lists to avoid memory spikes

Output envelope schema:
{
    "generated_at": str,        # ISO 8601 UTC timestamp
    "total_domains": int,
    "verdict_distribution": {}, # counts per verdict label
    "results": [ ... ]          # list of DomainResult dicts
}
"""

from __future__ import annotations


def write_results(results: list, output_path: str) -> None:
    """
    Serialise ``results`` to a JSON file at ``output_path``.

    Args:
        results:     List of DomainResult objects (or dicts).
        output_path: Destination file path (created if not exists).
    """
    raise NotImplementedError("write_results() not yet implemented — Phase 6.")
