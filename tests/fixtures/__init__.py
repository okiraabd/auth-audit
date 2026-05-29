"""
tests/fixtures/ — Static test fixture data for auth-audit unit tests.

This directory contains:
  - Sample proxy host JSON files in various shapes for loader tests
  - Pre-built ProbeResult / ProbeSet dicts for rule engine and signal extractor tests
  - Sample HTML snippets for html_summarizer tests

All fixture data is static — no network calls are made from tests.

Files (to be created per phase):
  proxy_hosts_standard.json   — Standard list[{domain: ...}] shape
  proxy_hosts_domain_names.json — List with domain_names key
  proxy_hosts_mixed.json      — Mix of enabled/disabled entries
  probe_basic_auth.json       — Probe set with 401 + WWW-Authenticate: Basic
  probe_open_api.json         — Probe set with /api returning JSON data
  probe_spa_shell.json        — Probe set where root is empty SPA shell
  html_login_form.html        — HTML with login form and password input
  html_spa_shell.html         — Minimal SPA shell HTML
  html_marketing_page.html    — Public marketing page with login link in nav
"""
