"""
tests/conftest.py — Shared pytest fixtures for auth-audit tests.

Provides:
  - ``fixtures_dir``   : Path to the tests/fixtures/ directory.
  - ``npm_hosts_file`` : Path to proxy_hosts_npm.json fixture.
  - ``simple_hosts_file`` : Path to proxy_hosts_simple.json fixture.
  - ``mixed_enabled_file`` : Path to proxy_hosts_mixed_enabled.json fixture.
  - ``invalid_entries_file``: Path to proxy_hosts_invalid.json fixture.
  - ``tmp_json_file``  : Factory fixture that writes a JSON payload to a temp
                         file and returns its Path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Path fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return the absolute path to tests/fixtures/."""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def npm_hosts_file(fixtures_dir: Path) -> Path:
    return fixtures_dir / "proxy_hosts_npm.json"


@pytest.fixture(scope="session")
def simple_hosts_file(fixtures_dir: Path) -> Path:
    return fixtures_dir / "proxy_hosts_simple.json"


@pytest.fixture(scope="session")
def mixed_enabled_file(fixtures_dir: Path) -> Path:
    return fixtures_dir / "proxy_hosts_mixed_enabled.json"


@pytest.fixture(scope="session")
def invalid_entries_file(fixtures_dir: Path) -> Path:
    return fixtures_dir / "proxy_hosts_invalid.json"


# ---------------------------------------------------------------------------
# Inline JSON factory fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_json_file(tmp_path: Path):
    """
    Factory fixture: write a Python object as JSON to a temp file.

    Usage::

        def test_something(tmp_json_file):
            path = tmp_json_file([{"domain": "a.internal"}])
            result = load_domains(path)
    """
    def _write(payload) -> Path:
        file = tmp_path / "proxy_hosts.json"
        file.write_text(json.dumps(payload), encoding="utf-8")
        return file

    return _write
