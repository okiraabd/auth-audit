# auth-audit 🔐

> A production-grade, 3-tier domain authentication detection pipeline.  
> Feed it a list of proxy hosts — it tells you exactly which ones are protected, open, or exposed.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [How It Works — The 3-Tier Pipeline](#how-it-works)
3. [Verdict Reference](#verdict-reference)
4. [Project Structure](#project-structure)
5. [Setup & Installation](#setup--installation)
6. [Configuration](#configuration)
7. [Input File Format](#input-file-format)
8. [Running the Pipeline](#running-the-pipeline)
9. [Output & Reports](#output--reports)
10. [Running Tests](#running-tests)
11. [Per-Phase Script Reference](#per-phase-script-reference)
12. [Requirements & Dependencies](#requirements--dependencies)

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

## How It Works

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
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
            results.jsonl  results.json  results.html
           (Streamed E2E)   (Final)       (Final)
```

### Verdict Priority

The final verdict is taken from the **highest tier that ran**. Tier 3 overrides Tier 2, which overrides Tier 1 — but only if the higher tier returned a confident, non-UNKNOWN verdict.

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

### Service Type Reference

The pipeline also classifies the underlying architecture of the domain:

| Service Type | Meaning |
|---|---|
| `WEB_APP` | HTML-based applications, including Single Page Applications (SPAs) like React/Vue. |
| `REST_API` | JSON-based API endpoints (includes S3 buckets returning XML/JSON errors). |
| `GRAPHQL` | GraphQL endpoints. |
| `MIXED` | A combination of a web frontend and API endpoints on the same domain. |
| `UNKNOWN` | Cannot determine service type. |

---

## Project Structure

```
auth-audit/
├── data/
│   └── proxy_hosts.json          # 📥 Your input file (edit this)
├── output/
│   ├── results.jsonl             # 💾 Intermediate checkpoints (streams E2E)
│   ├── results.json              # 📊 Machine-readable results (final)
│   ├── results.html              # 🌐 HTML dashboard (final)
│   └── screenshots/             # 📸 Browser screenshots from Hermes
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
│   │   ├── llm_client.py        # Async httpx client for Local LLM API
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

## Setup & Installation

### Prerequisites

- Python **3.11+**
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

### Full `.env` Reference

```dotenv
# ── Input / Output ────────────────────────────────────────────────
PROXY_HOSTS_FILE=data/proxy_hosts.json   # Path to your input JSON
OUTPUT_DIR=output                        # Where reports are saved
RESULTS_JSONL=output/results.jsonl
RESULTS_JSON=output/results.json
RESULTS_HTML=output/results.html
SCREENSHOTS_DIR=output/screenshots

# ── Active Discovery ─────────────────────────────────
DISCOVERY_ENABLED=true
DISCOVERY_TRIGGER_404_RATIO=0.9
KITERUNNER_ENABLED=false
# KITERUNNER_BINARY=kr
# KITERUNNER_WORDLIST=/path/to/routes.kite

# ── Data Gathering — HTTP Probing ─────────────────────────────────
PROBER_CONCURRENCY=10       # Max concurrent domain probes (1-200)
HTTP_TIMEOUT=15             # Per-request timeout in seconds
HTTP_MAX_REDIRECTS=10       # Max redirect hops to follow
BODY_PREVIEW_BYTES=8192     # Max bytes of body to capture per probe
HTTP_USER_AGENT=auth-audit/0.1 (security audit pipeline)

# ── Tier 2 — Local LLM Reasoning ──────────────────────────────────
LLM_BASE_URL=http://localhost:8000/v1   # Your LLM endpoint (Ollama, LM Studio, Local LLM…)
LLM_API_KEY=                            # Leave blank if not needed
LLM_MODEL=your-model-name              # Model to use
LLM_MAX_TOKENS=2048
LLM_TEMPERATURE=0.1
LLM_MAX_HTML_CHARS=4000         # Max chars of HTML sent to LLM
TIER2_ESCALATION_THRESHOLD=60   # Tier 1 score below this → always escalate

# ── Tier 3 — Hermes Browser Agent ────────────────────────────────
HERMES_BASE_URL=http://localhost:8080/v1   # Hermes API (OpenAI-compat)
HERMES_API_KEY=your-hermes-api-key
HERMES_TASK_TIMEOUT=120    # Seconds per browser task (browser is slow!)
HERMES_CONCURRENCY=1       # MUST be 1 to prevent screenshot bleed

# ── Retry / Resilience ───────────────────────────────────────────
HTTP_RETRY_ATTEMPTS=3
HTTP_RETRY_WAIT=1.0
LLM_RETRY_ATTEMPTS=2

# ── Logging ──────────────────────────────────────────────────────
LOG_LEVEL=INFO   # DEBUG | INFO | WARNING | ERROR
LOG_RICH=true    # Pretty Rich console output (true/false)

# ── Screenshot Storage (S3 / Ceph) ───────────────────────────────
# S3_ENDPOINT=http://s3.amazonaws.com
# S3_BUCKET=auth-audit-screenshots
# S3_ACCESS_KEY=your-access-key
# S3_SECRET_KEY=your-secret-key
# S3_SCREENSHOT_PREFIX=auth-audit/screenshots
```


> **Tip:** Any setting can also be passed as a real environment variable, which takes priority over `.env`. This is useful for CI/CD.

---

## Input File Format

The pipeline accepts two JSON formats.

### Format 1 — NPM (Nginx Proxy Manager export)

This is the native format exported from Nginx Proxy Manager:

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
  },
  {
    "id": 2,
    "domain_names": ["disabled.example.com"],
    "forward_scheme": "http",
    "forward_host": "192.168.1.11",
    "forward_port": 8080,
    "enabled": false          // ← this entry will be SKIPPED
  }
]
```

### Format 2 — Simple flat list

A simpler format if you don't have NPM data:

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

## Running the Pipeline

### Full E2E Run (recommended)

```bash
# Using default input (data/proxy_hosts.json) and output (output/)
python scripts/run_pipeline.py

# Custom input file
python scripts/run_pipeline.py --input data/my_hosts.json

# Custom output directory
python scripts/run_pipeline.py --input data/my_hosts.json --output-dir output/audit-2026

# Verbose debug logging
python scripts/run_pipeline.py --log-level DEBUG
```

### What you'll see in the terminal

```
╭──────────────────────────────────────────────────────────────╮
│ auth-audit — Authentication Detection Pipeline               │
│ Input:  data/proxy_hosts.json                                │
│ Output: output                                               │
╰──────────────────────────────────────────────────────────────╯

INFO  ▶ Active Discovery: Running route discovery for 2 domain(s)...
INFO  ▶ Tier 1: Probing 5 domain(s)...
INFO    app.example.com                  20+ paths OK
INFO    api.example.com                  20+ paths OK
...

INFO  ▶ Tier 2+3: Analyzing 5 domain(s)...
INFO  Escalating app.example.com to Tier 2 LLM...
INFO  [T3] Escalating app.example.com to Hermes...

┌───────────────────── Auth Audit Results — 5 domains ─────────────────────────┐
│ Domain                  │ Verdict             │ Service   │ Conf │ Tier │ Review │
├─────────────────────────┼─────────────────────┼───────────┼──────┼──────┼────────┤
│ app.example.com         │ 🔒 PROTECTED        │ MIXED     │  95% │  T3  │        │
│ api.example.com         │ 📄 OPEN_DOCS        │ REST_API  │  82% │  T1  │        │
│ admin.example.com       │ 🔒 PROTECTED        │ WEB_APP   │  90% │  T2  │        │
│ ...                     │ ...                 │ ...       │ ...  │ ...  │ ...    │
└──────────────────────────────────────────────────────────────────────────────┘

✓ JSON report: output/results.json
✓ HTML report: output/results.html
```

### Fault Tolerance & Checkpointing

The pipeline uses an **End-to-End (E2E) streaming architecture**. 
As soon as a domain completes Tier 3, it is instantly written to `output/results.jsonl`. 

If your internet drops, the API crashes, or you hit `Ctrl+C` after 5 hours, **you will not lose data.** 
When you restart the script, it will automatically:
1. Detect `results.jsonl`
2. Parse the completed domains
3. Skip them and seamlessly resume scanning the remaining domains

---

## Output & Reports

### S3 Cloud Reporting & Checkpointing

If S3 is configured in `.env` (`S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`), the pipeline will automatically:
1. **Periodic Checkpointing**: Upload `results.jsonl` to S3 every 50 domains. If the pipeline server crashes or restarts, your E2E state is safely stored in the cloud.
2. **Auto-Upload Reports**: At the end of the run, the pipeline uploads `results.html` and `results.json` into a timestamped folder (e.g., `auth-audit/reports/run_20260530_101500/results.html`), preserving historical audits.
3. **Latest Bookmark**: It also copies the report to `auth-audit/reports/latest/results.html`, giving you a permanent URL to bookmark for the most recent scan.

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

## Running Tests

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

### Python

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

## How Verdicts Are Decided

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
(Each tier only overrides if it returns a non-UNKNOWN result with confidence > 0)

---

*Built with Python 3.12 · Pydantic v2 · httpx · BeautifulSoup4 · Rich*
