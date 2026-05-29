"""
main.py — Entry point for the auth-audit pipeline.

Parses CLI arguments, bootstraps configuration and logging, then drives the
full multi-tier analysis workflow:

  1. Load domains from the proxy host JSON file
  2. Run Tier 1 async HTTP probing for all domains
  3. Escalate ambiguous cases to Tier 2 (Local LLM reasoning)
  4. Escalate remaining ambiguous cases to Tier 3 (Hermes browser automation)
  5. Write the final JSON results file
  6. Generate the HTML report

Business logic lives in the respective tier and utility modules.
This module is intentionally thin — it only wires components together.
"""

from __future__ import annotations


def main() -> None:
    """Entry point — orchestrates the full pipeline."""
    raise NotImplementedError("main() not yet implemented — see Phase 6 build order.")


if __name__ == "__main__":
    main()
