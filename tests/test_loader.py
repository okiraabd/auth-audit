"""
tests/test_loader.py — Unit tests for loaders.proxy_host_loader.

All tests are offline — no network I/O. Fixtures are loaded from
``tests/fixtures/`` or written inline via the ``tmp_json_file`` factory.

Coverage:
  - NPM shape (domain_names list, ssl_forced, enabled)
  - Simple shape (domain key)
  - Schema with scheme prefix in domain string (should be stripped)
  - Multi-domain entry (one NPM proxy host → multiple Domain objects)
  - Disabled entries are skipped (enabled=false)
  - Entries without an enabled flag are included
  - Domain deduplication (case-insensitive; first occurrence wins)
  - Invalid entries are skipped without raising (non-dict, empty domain_names, whitespace)
  - Only valid entries survive when mixed with invalid ones
  - Empty JSON array returns empty list
  - Malformed JSON raises ValueError
  - Missing file raises FileNotFoundError
  - JSON object (not array) at top level raises ValueError
  - probe_scheme is "https" when ssl_forced=true
  - probe_scheme is "http" when ssl_forced=false and forward_scheme="http"
  - source_id is correctly populated from "id" field
  - raw_entry is preserved on Domain object
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import sys

# ---------------------------------------------------------------------------
# Make src/ importable when running tests from the repo root.
# pytest.ini / pyproject.toml testpaths points to tests/, but src/ is not
# automatically on sys.path in all environments.
# ---------------------------------------------------------------------------
SRC_DIR = Path(__file__).parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from loaders.proxy_host_loader import load_domains  # noqa: E402
from models.domain import Domain  # noqa: E402


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _hostnames(domains: list[Domain]) -> list[str]:
    """Return a list of hostnames from a Domain list."""
    return [d.hostname for d in domains]


# ---------------------------------------------------------------------------
# NPM shape
# ---------------------------------------------------------------------------


class TestNpmShape:
    def test_loads_correct_count(self, npm_hosts_file: Path):
        """NPM fixture has 3 entries; the multi-domain entry adds 2 extra hostnames."""
        domains = load_domains(npm_hosts_file)
        # id=3 → 1, id=4 → 1, id=5 → 2 domains
        assert len(domains) == 4

    def test_hostnames_are_correct(self, npm_hosts_file: Path):
        domains = load_domains(npm_hosts_file)
        hostnames = _hostnames(domains)
        assert "app.example.internal" in hostnames
        assert "api.example.internal" in hostnames
        assert "multi1.example.internal" in hostnames
        assert "multi2.example.internal" in hostnames

    def test_ssl_forced_true_gives_https(self, npm_hosts_file: Path):
        domains = load_domains(npm_hosts_file)
        app_domain = next(d for d in domains if d.hostname == "app.example.internal")
        assert app_domain.probe_scheme == "https"

    def test_ssl_forced_false_forward_http_gives_http(self, npm_hosts_file: Path):
        """id=5 has ssl_forced=false and forward_scheme=http (implicit) → http."""
        domains = load_domains(npm_hosts_file)
        multi = next(d for d in domains if d.hostname == "multi1.example.internal")
        assert multi.probe_scheme == "http"

    def test_source_id_populated(self, npm_hosts_file: Path):
        domains = load_domains(npm_hosts_file)
        app_domain = next(d for d in domains if d.hostname == "app.example.internal")
        assert app_domain.source_id == 3

    def test_raw_entry_preserved(self, npm_hosts_file: Path):
        domains = load_domains(npm_hosts_file)
        app_domain = next(d for d in domains if d.hostname == "app.example.internal")
        assert "forward_host" in app_domain.raw_entry
        assert app_domain.raw_entry["forward_port"] == 17227

    def test_returns_domain_instances(self, npm_hosts_file: Path):
        domains = load_domains(npm_hosts_file)
        assert all(isinstance(d, Domain) for d in domains)

    def test_probe_base_url_formed_correctly(self, npm_hosts_file: Path):
        domains = load_domains(npm_hosts_file)
        app = next(d for d in domains if d.hostname == "app.example.internal")
        assert app.probe_base_url == "https://app.example.internal"


# ---------------------------------------------------------------------------
# Simple domain-key shape
# ---------------------------------------------------------------------------


class TestSimpleShape:
    def test_loads_all_simple_entries(self, simple_hosts_file: Path):
        domains = load_domains(simple_hosts_file)
        assert len(domains) == 3

    def test_scheme_stripped_from_domain_value(self, simple_hosts_file: Path):
        """Entry with 'https://simple-c.example.internal/' should normalise cleanly."""
        domains = load_domains(simple_hosts_file)
        assert "simple-c.example.internal" in _hostnames(domains)
        # No scheme in the hostname
        for d in domains:
            assert "://" not in d.hostname

    def test_no_enabled_flag_included(self, simple_hosts_file: Path):
        """simple-a has no enabled flag → should be included."""
        domains = load_domains(simple_hosts_file)
        assert "simple-a.example.internal" in _hostnames(domains)

    def test_default_scheme_is_https(self, simple_hosts_file: Path):
        domains = load_domains(simple_hosts_file)
        assert all(d.probe_scheme == "https" for d in domains)


# ---------------------------------------------------------------------------
# enabled flag filtering
# ---------------------------------------------------------------------------


class TestEnabledFilter:
    def test_disabled_entries_skipped(self, mixed_enabled_file: Path):
        domains = load_domains(mixed_enabled_file)
        hostnames = _hostnames(domains)
        assert "disabled-b.example.internal" not in hostnames
        assert "disabled-d.example.internal" not in hostnames

    def test_enabled_entries_included(self, mixed_enabled_file: Path):
        domains = load_domains(mixed_enabled_file)
        assert "enabled-a.example.internal" in _hostnames(domains)

    def test_no_flag_entry_included(self, mixed_enabled_file: Path):
        """noflag-c has no 'enabled' key → should be included."""
        domains = load_domains(mixed_enabled_file)
        assert "noflag-c.example.internal" in _hostnames(domains)

    def test_correct_count_after_filter(self, mixed_enabled_file: Path):
        """id=10 (enabled) + id=12 (no flag) = 2 domains."""
        domains = load_domains(mixed_enabled_file)
        assert len(domains) == 2


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_duplicate_hostnames_deduplicated(self, tmp_json_file):
        payload = [
            {"domain_names": ["dup.example.internal"], "ssl_forced": True, "enabled": True},
            {"domain_names": ["dup.example.internal"], "ssl_forced": True, "enabled": True},
            {"domain_names": ["DUP.EXAMPLE.INTERNAL"], "ssl_forced": True, "enabled": True},
        ]
        domains = load_domains(tmp_json_file(payload))
        assert len(domains) == 1
        assert domains[0].hostname == "dup.example.internal"

    def test_dedup_preserves_first_occurrence(self, tmp_json_file):
        payload = [
            {"id": 1, "domain_names": ["dup.example.internal"], "ssl_forced": True, "enabled": True},
            {"id": 2, "domain_names": ["dup.example.internal"], "ssl_forced": False, "enabled": True},
        ]
        domains = load_domains(tmp_json_file(payload))
        assert domains[0].source_id == 1


# ---------------------------------------------------------------------------
# Invalid entries
# ---------------------------------------------------------------------------


class TestInvalidEntries:
    def test_valid_entry_survives_with_invalids(self, invalid_entries_file: Path):
        """Only the single valid entry (id=20) should be returned."""
        domains = load_domains(invalid_entries_file)
        assert len(domains) == 1
        assert domains[0].hostname == "valid.example.internal"

    def test_empty_domain_names_list_skipped(self, tmp_json_file):
        payload = [{"id": 99, "domain_names": [], "ssl_forced": True, "enabled": True}]
        domains = load_domains(tmp_json_file(payload))
        assert domains == []

    def test_whitespace_only_domain_skipped(self, tmp_json_file):
        payload = [{"domain_names": ["   "], "ssl_forced": True, "enabled": True}]
        domains = load_domains(tmp_json_file(payload))
        assert domains == []

    def test_non_dict_entries_skipped(self, tmp_json_file):
        payload = ["not_a_dict", 42, None, {"domain_names": ["valid.example.internal"], "enabled": True}]
        domains = load_domains(tmp_json_file(payload))
        assert len(domains) == 1

    def test_entry_without_domain_field_skipped(self, tmp_json_file):
        payload = [{"id": 1, "forward_host": "10.0.0.1", "enabled": True}]
        domains = load_domains(tmp_json_file(payload))
        assert domains == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_array_returns_empty_list(self, tmp_json_file):
        domains = load_domains(tmp_json_file([]))
        assert domains == []

    def test_file_not_found_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_domains(tmp_path / "nonexistent.json")

    def test_malformed_json_raises_value_error(self, tmp_path: Path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ this is not json", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_domains(bad_file)

    def test_top_level_dict_raises_value_error(self, tmp_json_file):
        with pytest.raises(ValueError, match="JSON array"):
            load_domains(tmp_json_file({"domain": "example.com"}))

    def test_domains_are_lowercase(self, tmp_json_file):
        payload = [{"domain_names": ["UPPER.EXAMPLE.INTERNAL"], "ssl_forced": True, "enabled": True}]
        domains = load_domains(tmp_json_file(payload))
        assert domains[0].hostname == "upper.example.internal"

    def test_host_key_shape(self, tmp_json_file):
        """Test the 'host' field alternative shape."""
        payload = [{"host": "host-shape.example.internal"}]
        domains = load_domains(tmp_json_file(payload))
        assert len(domains) == 1
        assert domains[0].hostname == "host-shape.example.internal"
