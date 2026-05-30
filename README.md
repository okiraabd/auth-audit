# auth-audit 🔐

> A production-grade, multi-tier domain authentication detection pipeline. Feed it a list of proxy hosts — it tells you exactly which ones are protected, open, or exposed.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Pydantic v2](https://img.shields.io/badge/pydantic-v2-green.svg)](https://docs.pydantic.dev/latest/)

---

## Table of Contents

1. [Overview](#overview)
2. [What It Does](#what-it-does)
3. [Architecture — The 3-Tier Pipeline](#architecture--the-3-tier-pipeline)
4. [Project Structure](#project-structure)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Input File Format](#input-file-format)
8. [Usage](#usage)
9. [Output & Reports](#output--reports)
10. [Verdict Reference](#verdict-reference)
11. [Service Type Reference](#service-type-reference)
12. [Verdict Decision Logic](#verdict-decision-logic)
13. [Testing](#testing)
14. [Per-Phase Script Reference](#per-phase-script-reference)
15. [Requirements & Dependencies](#requirements--dependencies)
16. [Kiterunner Integration](#kiterunner-integration)
17. [Troubleshooting](#troubleshooting)
18. [Contributing](#contributing)
19. [License](#license)

---

## Overview

`auth-audit` is a Python-based security audit pipeline that determines the authentication status of a list of domains. It uses a progressive escalation strategy — starting with fast, deterministic HTTP probing, then escalating to LLM reasoning, and finally to real browser automation when needed.

### Key Features

- **3-Tier Progressive Escalation**: Fast HTTP probes → LLM reasoning → Browser automation
- **Async Architecture**: High concurrency with `asyncio` and `httpx`
- **Checkpointing**: End-to-end JSONL streaming — no data loss on crash
- **S3 Cloud Reporting**: Automatic upload of results to S3-compatible storage
- **Rich HTML Dashboard**: Self-contained, offline-capable report
- **Active Discovery**: Automatic route discovery for domains with mostly 404 responses
- **Kiterunner Integration**: Optional high-performance route discovery using kiterunner (520k routes)
- **91 Unit Tests**: Full coverage across all modules

---

## What It Does

`auth-audit` audits a list of domains (read from a proxy host JSON file) and determines, for each domain:

| Question | Answer |
|---|---|
| Is it reachable? | ✅ Yes / 💀 Unreachable |
| What type of service is it? | Web App, REST API, GraphQL, Mixed |
| Is it protected by auth? | 🔒 Protected / ⚠️ Partial / 🔓 Open |
| How exposed is it? | 🚨 Critical exposure / 📄 Docs leak |
| Does it need manual review? | ⚑ Flagged for human review |

It produces a **JSON results file** and a **rich interactive HTML dashboard** from a single command.

---

## Architecture — The 3-Tier Pipeline

The pipeline uses a **3-tier progressive escalation** strategy. Each domain only escalates to the next tier if the current one can't reach a confident verdict. This keeps the pipeline fast for easy cases and thorough for hard ones.

```text
┌──────────────────────────────────────────────────────┐
│ DATA GATHERING (Fast, Bulk)                          │
│  • Concurrently probes common standard paths (/, /api)   │
└──────────────────────────────┬───────────────────────┘
                              │
       [Are >90% of successful probes returning 404?]
           / Yes                                 \ No
          ▼                                       │
┌────────────────────────────┐                    │
│ ACTIVE DISCOVERY DETOUR    │                    │
│  • Brute-force wordlist    │                    │
│  • Merge discovered paths  │                    │
└─────────┬──────────────────┘                    │
          └────────────────────► ┬ ◄──────────────┘
                                 ▼
┌──────────────────────────────────────────────────────┐
│ TIER 1 — Rule Engine Evaluation                      │
│  • Extracts signals (401, CORS, login forms)         │
│  • Deterministic rule engine → initial verdict       │
└──────────────────────────────┬───────────────────────┘
                              │ [If score < 60 or ambiguous]
                              ▼
┌──────────────────────────────────────────────────────┐
│ TIER 2 — LLM Reasoning (OpenAI-compatible endpoint)  │
│                                                      │
│  • Summarises HTML response (forms, headings, meta)  │
│  • Strips boilerplate, detects SPA shells            │
│  • Asks LLM: "What auth mechanisms does this use?"   │
│  • Returns verdict + reasoning + confidence          │
│  • If SPA shell / JS wall → escalate to Tier 3      │
└──────────────────────────────┬───────────────────────┘
                              │ needs_browser=True
                              ▼
┌──────────────────────────────────────────────────────┐
│ TIER 3 — Hermes Browser Agent (real browser, on-demand)│
│                                                      │
│  • Hermes is an agentic LLM with real browser tools  │
│    (navigate, click, scroll, screenshot)             │
│  • Visits the URL, waits for JS to execute           │
│  • Interacts with login CTAs if present              │
│  • Returns JSON verdict with visual evidence         │
└──────────────────────────────┬───────────────────────┘
                              │
                              ▼
                    DomainResult (final)
                               │
                  ┌────────────┼────────────┐
                  ▼            ▼            ▼
           results.jsonl  results.json  results.html
          (Streamed E2E)   (Final)       (Final)
```

### Verdict Priority

The final verdict is taken from the **highest tier that ran**. Tier 3 overrides Tier 2, which overrides Tier 1 — but only if the higher tier returned a confident, non-UNKNOWN verdict.

---

## Project Structure

```
auth-audit/
├── data/
│   └── proxy_hosts.json          # 📥 Your input file (edit this)
├── output/
│   ├── results.jsonl             # 💾 Intermediate checkpoints (streams E2E)
│   ├── results.json              # 📊 Machine-readable results (final)
│   └── results.html              # 🌐 HTML dashboard (final)
│
├── scripts/
│   ├── run_pipeline.py           # 🚀 Main E2E runner
│   ├── test_phase5_hermes.py     # 🧪 Standalone Hermes test
│   └── test_phase4_tier2.py      # 🧪 Standalone LLM test
│
├── src/
│   ├── config.py                 # ⚙️ All settings (env-based, Pydantic)
│   ├── main.py                   # Entry point (calls pipeline)
│   │
│   ├── loaders/
│   │   └── proxy_host_loader.py  # Parses input JSON → Domain objects
│   │
│   ├── models/
│   │   ├── domain.py             # Domain model (hostname, scheme, probe URL)
│   │   ├── probes.py             # ProbeResult, ProbeSet (raw HTTP data)
│   │   └── result.py             # DomainResult (final output schema)
│   │
│   ├── discovery/
│   │   ├── wordlist.py           # Bundled curated API/auth wordlist
│   │   └── route_discoverer.py   # Active route discovery logic (wordlist/kr)
│   │
│   ├── prober/
│   │   ├── http_prober.py        # Async HTTP prober (common paths, GraphQL POST)
│   │   └── path_strategy.py      # Path lists and category classification
│   │
│   ├── tier1/
│   │   ├── signal_extractor.py   # Extracts 20+ labelled signals from probes
│   │   └── rule_engine.py        # Deterministic rules → verdict + score
│   │
│   ├── tier2/
│   │   ├── html_summarizer.py    # Condenses HTML to ~4000 chars for LLM
│   │   ├── llm_client.py         # Async httpx client for Local LLM API
│   │   ├── prompts.py            # System prompt + resilient JSON parser
│   │   └── llm_analyzer.py       # Orchestrates Tier 2 escalation
│   │
│   ├── tier3/
│   │   ├── hermes_client.py      # Chat-based Hermes client (browser agent)
│   │   └── hermes_tasks.py       # Builds task payloads for Hermes
│   │
│   ├── orchestration/
│   │   └── pipeline.py           # Main pipeline: Tier 1 → 2 → 3
│   │
│   ├── reporting/
│   │   ├── json_report.py        # Writes results.json
│   │   └── html_report.py        # Generates HTML dashboard
│   │
│   └── utils/
│       ├── retry.py              # Async retry with exponential backoff
│       └── urls.py               # URL builder helpers
│
├── tests/                        # 91 pytest tests across all modules
├── .env.example                  # Template — copy to .env and fill in
├── pyproject.toml                # Project metadata + pytest config
└── requirements.txt              # Runtime + dev dependencies
```

---

## Installation

### Prerequisites

- **Python 3.11+**
- Access to a **local LLM endpoint** (OpenAI-compatible, e.g. Ollama, LM Studio, Local LLM) for Tier 2
- Access to the **Hermes Agent API** (Tier 3 browser automation)

### Install

```bash
# 1. Clone the repo and enter the project directory
cd auth-audit

# 2. (Optional but recommended) Create a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy the example environment file
cp .env.example .env
```

---

## Configuration

All configuration is done via environment variables or the `.env` file. The pipeline reads `.env` automatically from the working directory.

### Quick Start `.env`

```dotenv
# ── Input / Output ────────────────────────────────────────────────
PROXY_HOSTS_FILE=data/proxy_hosts.json
OUTPUT_DIR=output
RESULTS_JSON=output/results.json
RESULTS_HTML=output/results.html

# ── HTTP Probing ──────────────────────────────────────────────────
PROBER_CONCURRENCY=10
HTTP_TIMEOUT=15
HTTP_MAX_REDIRECTS=10
BODY_PREVIEW_BYTES=8192
HTTP_USER_AGENT=auth-audit/0.1 (security audit pipeline)

# ── Tier 2 — Local LLM ────────────────────────────────────────────
LLM_BASE_URL=http://localhost:8000/v1
LLM_MODEL=qwen3.6-27b
LLM_MAX_TOKENS=2048
LLM_TEMPERATURE=0.1
LLM_CONCURRENCY=5
LLM_TIMEOUT=120.0
TIER2_ESCALATION_THRESHOLD=60

# ── Tier 3 — Hermes Browser Agent ────────────────────────────────
HERMES_BASE_URL=http://localhost:8080/v1
HERMES_API_KEY=your-hermes-api-key
HERMES_TASK_TIMEOUT=120
HERMES_CONCURRENCY=5
```

> **Tip:** Any setting can also be passed as a real environment variable, which takes priority over `.env`. This is useful for CI/CD.

### Full Configuration Reference

See [`.env.example`](.env.example) for the complete list of configuration options with detailed comments.

---

## Input File Format

The pipeline accepts two JSON formats.

### Format 1 — NPM (Nginx Proxy Manager export)

```json
[
  {
    "id": 1,
    "domain_names": ["app.example.com"],
    "forward_scheme": "https",
    "forward_host": "192.168.1.10",
    "forward_port": 443,
    "ssl_forced": true,
    "enabled": true
  }
]
```

### Format 2 — Simple flat list

```json
[
  { "domain": "app.example.com" },
  { "domain": "api.example.com", "enabled": true },
  { "domain": "internal.example.com" }
]
```

### Rules

- Entries with `"enabled": false` are **skipped**.
- Duplicate hostnames are **deduplicated** (first occurrence wins).
- Invalid or blank entries are **skipped** with a warning.
- The default input file is `data/proxy_hosts.json`.

---

## Usage

### Full E2E Run (recommended)

```bash
# Basic run
python scripts/run_pipeline.py

# Run with custom input and output directories
python scripts/run_pipeline.py --input data/my_hosts.json --output-dir output/run1
```

### Regenerating HTML Reports
If the pipeline is interrupted or you want to update the report's design without rescanning, you can instantly regenerate the `results.html` file from an existing JSONL checkpoint:

```bash
# Generate the HTML locally
python scripts/generate_html.py --input output/results.jsonl --output output/recovered.html

# Limit to first 100 domains for quick testing
python scripts/generate_html.py --input output/results.jsonl --limit 100

# Upload the regenerated report directly to S3 (lands in a 'recovered' folder by default)
python scripts/generate_html.py --input output/results.jsonl --upload-s3

# Danger: Overwrite the main latest/results.html dashboard in S3 with the recovered report
python scripts/generate_html.py --input output/results.jsonl --upload-s3 --update-latest
```

### What you'll see in the terminal

```
╭──────────────────────────────────────────────────────────────╮
│ auth-audit — Authentication Detection Pipeline               │
│ Input:  data/proxy_hosts.json                                │
│ Output: output                                               │
╰──────────────────────────────────────────────────────────────╯

INFO  ▶ Tier 1: Probing 5 domain(s)...
INFO    app.example.com                  20+ paths OK
INFO    api.example.com                  20+ paths OK

INFO  ▶ Tier 2+3: Analyzing 5 domain(s)...
INFO  Escalating app.example.com to Tier 2 LLM...
INFO  [T3] Escalating app.example.com to Hermes...

┌───────────────────── Auth Audit Results — 5 domains ─────────────────────────┐
│ Domain                  │ Verdict             │ Service   │ Conf │ Tier │ Review │
├─────────────────────────┼─────────────────────┼───────────┼──────┼──────┼────────┤
│ app.example.com         │ 🔒 PROTECTED        │ MIXED     │  95% │  T3  │        │
│ api.example.com         │ 📄 OPEN_DOCS        │ REST_API  │  82% │  T1  │        │
└──────────────────────────────────────────────────────────────────────────────┘

✓ JSON report: output/results.json
✓ HTML report: output/results.html
```

### Fault Tolerance & Checkpointing

The pipeline uses an **End-to-End (E2E) streaming architecture**. As soon as a domain completes Tier 3, it is instantly written to `output/results.jsonl`.

If your internet drops, the API crashes, or you hit `Ctrl+C` after 5 hours, **you will not lose data.** When you restart the script, it will automatically:

1. Detect `results.jsonl`
2. Parse the completed domains
3. Skip them and seamlessly resume scanning the remaining domains

---

## Output & Reports

### S3 Cloud Reporting & Checkpointing

If S3 is configured in `.env` (`S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`), the pipeline will automatically:

1. **Periodic Checkpointing**: Upload `results.jsonl` to S3 every 50 domains
2. **Auto-Upload Reports**: At the end of the run, the pipeline uploads `results.html` and `results.json` into a timestamped folder
3. **Latest Bookmark**: It also copies the report to `auth-audit/reports/latest/results.html`

### `output/results.json`

A structured JSON file containing the full result for every domain:

```json
{
  "generated_at": "2026-01-15T08:00:00Z",
  "total": 5,
  "summary": {
    "PROTECTED": 3,
    "OPEN_DOCS": 1,
    "UNKNOWN": 1
  },
  "results": [
    {
      "domain": "app.example.com",
      "service_type": "MIXED",
      "final_verdict": "PROTECTED",
      "confidence": 95,
      "tier_reached": 3,
      "signals": ["R_SPA_SHELL", "R_AUTH_REDIRECT_PATH", "R_PASSWORD_FIELD"],
      "reasoning": "Browser confirmed: root URL redirects to /auth/login with a standard username/password form.",
      "tier1_output": { "...": "..." },
      "tier2_output": { "...": "..." },
      "tier3_output": { "...": "..." }
    }
  ]
}
```

### `output/results.html`

A fully self-contained HTML dashboard (no CDN dependencies) with:

- **Summary cards** — per-verdict counts at a glance
- **Filter bar** — search by domain name, filter by verdict or service type
- **Sortable table** — click any column header to sort
- **Detail panels** — click any row to expand: signals, LLM reasoning, browser interaction steps, screenshots
- **Dark glassmorphism theme** — looks great on any screen

> Open `output/results.html` in any browser — it works fully offline.

---

## Verdict Reference

| Verdict | Emoji | Meaning |
|---|---|---|
| `PROTECTED` | 🔒 | Strong auth; login required to access anything |
| `PARTIAL` | ⚠️ | Some paths protected, others not |
| `OPEN` | 🔓 | Public content, no auth required |
| `OPEN_API` | 🔓 | REST API reachable without auth (data unclear) |
| `OPEN_API_CRITICAL` | 🚨 | REST API exposing sensitive data without auth |
| `OPEN_DOCS` | 📄 | Swagger / OpenAPI / Redoc docs exposed without auth |
| `GRAPHQL_OPEN` | 🔓 | GraphQL endpoint reachable; introspection unknown |
| `GRAPHQL_CRITICAL` | 🚨 | GraphQL schema/introspection fully exposed without auth |
| `UNREACHABLE` | 💀 | Domain could not be reached on any probed path |
| `UNKNOWN` | ❓ | Insufficient evidence; manual review recommended |

---

## Service Type Reference

| Service Type | Meaning |
|---|---|
| `WEB_APP` | HTML-based applications, including Single Page Applications (SPAs) like React/Vue. |
| `REST_API` | JSON-based API endpoints (includes S3 buckets returning XML/JSON errors). |
| `GRAPHQL` | GraphQL endpoints. |
| `MIXED` | A combination of a web frontend and API endpoints on the same domain. |
| `UNKNOWN` | Cannot determine service type. |

---

## Verdict Decision Logic

```
Tier 1 Rule Engine Score
  │
  ├── ≥ 80  →  High confidence verdict from Tier 1 (no escalation)
  │
  ├── 60–79 →  Medium confidence: escalate to Tier 2 LLM
  │               LLM refines verdict and confidence
  │               If LLM says needs_browser=True → escalate to Tier 3
  │
  └── < 60  →  Low confidence: always escalate to Tier 2
                LLM refines, may further escalate to Tier 3
```

**When does Tier 3 trigger?**

The LLM in Tier 2 sets `needs_browser_escalation=true` when it detects a **WEB_APP** that cannot be evaluated statically:

- **0-Character HTML Bodies**: The page returns a completely empty visual text payload (e.g. `soup.get_text()` is empty), which is a definitive signature of a modern SPA shell requiring JavaScript execution.
- **SPA Shells**: Tiny HTML bodies (e.g., `<div id="root"></div>`) that load React/Vue/Angular bundles.
- **Dynamic Content**: The page returns generic loading content that changes after JS runs.
- **Static Ambiguity**: The LLM cannot determine auth status from static HTML alone.

**Final verdict priority:** Tier 3 > Tier 2 > Tier 1

---

## Testing

```bash
# Run all 91 tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_rule_engine.py -v

# Run tests matching a keyword
python -m pytest tests/ -v -k "protected"

# Run with short failure output
python -m pytest tests/ --tb=short
```

### Test coverage by module

| Test File | Tests | What It Covers |
|---|---|---|
| `test_loader.py` | 24 | Domain loading, dedup, NPM/simple formats, error handling |
| `test_rule_engine.py` | 29 | All verdict rules, service type detection, output schema |
| `test_service_classifier.py` | 12 | REST/GraphQL/WebApp/Mixed service type edge cases |
| `test_html_summarizer.py` | 7 | HTML extraction, SPA detection, truncation |
| `test_prompts.py` | 7 | Prompt builder, JSON parser robustness, think-block stripping |
| `test_hermes_client.py` | 11 | Task builder, JSON parser, mocked HTTP client |
| **Total** | **91** | **All passing ✅** |

---

## Per-Phase Script Reference

These scripts let you test individual pipeline tiers in isolation — useful for debugging or tuning.

### Test Prober (Data Gathering) on a single domain

```bash
$env:PYTHONPATH="src"
python scripts/test_phase2_prober.py --domain app.example.com
```

### Test Tier 2 (LLM) on a single domain

```bash
$env:PYTHONPATH="src"
python scripts/test_phase4_tier2.py --domain app.example.com
```

### Test Tier 3 (Hermes Browser Agent) on a single domain

```bash
$env:PYTHONPATH="src"
$env:HERMES_BASE_URL="http://localhost:8080/v1"
$env:HERMES_API_KEY="your-hermes-api-key"
python scripts/test_phase5_hermes.py --domain app.example.com --reason "SPA shell, need browser"
```

Sample output:

```
┌───────────── Hermes Browser Agent — app.example.com ─────────────┐
│ Verdict      : PROTECTED                                          │
│ Confidence   : 95                                                 │
│ Evidence     : Login page at /auth/login                          │
│ Reasoning    : Root URL redirects to /auth/login. Standard        │
│                username+password form detected.                   │
│ Screenshots  : 1 captured                                         │
│ Interactions : 5 steps                                            │
└───────────────────────────────────────────────────────────────────┘
```

---

## Requirements & Dependencies

### Python Packages

| Package | Purpose |
|---|---|
| `httpx>=0.27` | Async HTTP client (Tier 1 probing + LLM/Hermes API calls) |
| `pydantic>=2.7` | Data validation and settings management |
| `pydantic-settings>=2.3` | `.env` file loading |
| `beautifulsoup4>=4.12` | HTML parsing for Tier 2 summariser |
| `lxml>=5.2` | Fast HTML parser backend |
| `jinja2>=3.1` | (Reserved for future template use) |
| `rich>=13.7` | Terminal output formatting |
| `orjson>=3.10` | Fast JSON serialization |
| `python-dotenv>=1.0` | `.env` file support |
| `boto3>=1.34` | S3 cloud reporting |
| `pytest>=8.2` | Test runner |
| `pytest-asyncio>=0.23` | Async test support |

### External Services

| Service | Used For | Configure via |
|---|---|---|
| **Local LLM** (OpenAI-compat) | Tier 2 — static analysis & reasoning | `LLM_BASE_URL` in `.env` |
| **Hermes Agent** (OpenAI-compat) | Tier 3 — real browser automation | `HERMES_BASE_URL` in `.env` |

Both services must expose an **OpenAI-compatible Chat Completions API** (`POST /v1/chat/completions`). You can use any compatible backend — Ollama, LM Studio, Local LLM, OpenAI, Azure OpenAI, etc.

> **Hermes** must be an *agentic* model with browser tools (navigate, click, screenshot). A plain LLM without browser capability will not work for Tier 3.

---

## Kiterunner Integration

**Kiterunner** is an optional, high-performance route discovery tool that can be used instead of (or in addition to) the bundled wordlist. It uses a massive curated wordlist of **520k routes** for comprehensive API endpoint discovery.

### How it works

When a domain returns mostly 404 responses during initial probing, the pipeline triggers **Active Discovery** to find hidden routes:

1. **Bundled wordlist** (always available) — Probes a curated list of common API/auth paths
2. **Kiterunner** (optional) — If enabled and available, runs the `kr` binary for deeper scanning

### Prerequisites

- [Kiterunner](https://github.com/assetnote/kiterunner) installed and available on `PATH`
- `kr` command accessible from terminal

### Configuration

Set the following in your `.env`:

```dotenv
# Enable kiterunner
KITERUNNER_ENABLED=true

# Path to kiterunner binary (default: kr)
# KITERUNNER_BINARY=kr

# Path to kiterunner wordlist file (default: routes.kite in CWD)
# KITERUNNER_WORDLIST=/path/to/routes.kite

# Concurrent threads for scanning (default: 3)
# KITERUNNER_CONCURRENCY=3

# Timeout in seconds (default: 120)
# KITERUNNER_TIMEOUT=120
```

### When to use kiterunner

| Scenario | Recommendation |
|---|---|
| Quick audit, few domains | Bundled wordlist is sufficient |
| Large-scale audit, many domains | Enable kiterunner for better coverage |
| Domains with custom API paths | Kiterunner recommended (520k routes) |
| Limited bandwidth/time | Use bundled wordlist only |

### Verification

To verify kiterunner is available:

```bash
# Check if kr is on PATH
kr --version

# If not found, install from https://github.com/assetnote/kiterunner
```

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---|---|
| `Connection refused` on LLM calls | Check that your LLM server is running on the configured port |
| `LLM_TIMEOUT` | Increase `LLM_MAX_TOKENS` or check LLM server load |
| `Hermes task timeout` | Increase `HERMES_TASK_TIMEOUT` (browser tasks are slow) |
| All domains show `UNREACHABLE` | Check network connectivity and proxy configuration |
| `results.jsonl` not found | Run the pipeline at least once to create the checkpoint |

### Debug Mode

```bash
# Enable debug logging for detailed output
python scripts/run_pipeline.py --log-level DEBUG

# Or set in .env
LOG_LEVEL=DEBUG
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Write or update tests as needed
5. Ensure all tests pass (`python -m pytest tests/ -v`)
6. Submit a pull request

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Built with Python 3.12 · Pydantic v2 · httpx · BeautifulSoup4 · Rich*