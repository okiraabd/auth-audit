"""
reporting/html_report.py — Premium HTML dashboard for audit results.

Generates a fully self-contained HTML file (no external CDN dependencies)
with a dark glassmorphism theme, verdict summary cards, filterable domain
table, and per-domain detail panels with screenshots and LLM reasoning.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from models.result import DomainResult, Verdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Verdict styling config
# ---------------------------------------------------------------------------
_VERDICT_STYLE = {
    "PROTECTED":        {"emoji": "🔒", "color": "#22c55e", "bg": "rgba(34,197,94,0.15)"},
    "PARTIAL":          {"emoji": "⚠️",  "color": "#f59e0b", "bg": "rgba(245,158,11,0.15)"},
    "OPEN":             {"emoji": "🔓", "color": "#3b82f6", "bg": "rgba(59,130,246,0.15)"},
    "OPEN_API":         {"emoji": "🔓", "color": "#f97316", "bg": "rgba(249,115,22,0.15)"},
    "OPEN_API_CRITICAL":{"emoji": "🚨", "color": "#ef4444", "bg": "rgba(239,68,68,0.15)"},
    "OPEN_DOCS":        {"emoji": "📄", "color": "#a78bfa", "bg": "rgba(167,139,250,0.15)"},
    "GRAPHQL_OPEN":     {"emoji": "🔓", "color": "#f97316", "bg": "rgba(249,115,22,0.15)"},
    "GRAPHQL_CRITICAL": {"emoji": "🚨", "color": "#ef4444", "bg": "rgba(239,68,68,0.15)"},
    "UNREACHABLE":      {"emoji": "💀", "color": "#6b7280", "bg": "rgba(107,114,128,0.15)"},
    "UNKNOWN":          {"emoji": "❓", "color": "#94a3b8", "bg": "rgba(148,163,184,0.15)"},
}


def _verdict_style(verdict: str) -> dict:
    return _VERDICT_STYLE.get(verdict, _VERDICT_STYLE["UNKNOWN"])

# ---------------------------------------------------------------------------
# Signal descriptions for tooltips
# ---------------------------------------------------------------------------
_SIGNAL_DESC = {
    "R_401_BASIC": "401 Unauthorized with Basic Auth",
    "R_401_DIGEST": "401 Unauthorized with Digest Auth",
    "R_401_BEARER": "401 Unauthorized with Bearer Auth",
    "R_403_FORBIDDEN": "403 Forbidden on a probed path",
    "R_AUTH_REDIRECT_PATH": "Redirected to a known auth/login path",
    "R_AUTH_REDIRECT_EXTERNAL": "Redirected to an external domain (SSO/OAuth)",
    "R_AUTH_REDIRECT_PROVIDER": "Redirected to a known Identity Provider (Authelia, Keycloak, etc.)",
    "R_PASSWORD_FIELD": "Found <input type='password'> in HTML",
    "R_LOGIN_FORM": "Found a <form> with a login-like action",
    "R_LOGIN_KEYWORD": "Found 'login', 'sign in', or similar keywords in text",
    "R_SESSION_COOKIE": "Found a session/auth cookie in Set-Cookie header",
    "R_JSON_CONTENT_TYPE": "Response Content-Type is application/json",
    "R_JSON_BODY": "Response body is valid JSON",
    "R_HTML_RESPONSE": "Response is valid HTML",
    "R_GRAPHQL_RESPONSE": "JSON contains GraphQL 'data' or 'errors' keys",
    "R_GRAPHQL_INTROSPECTION": "GraphQL introspection query succeeded (__schema)",
    "R_SWAGGER_MARKER": "Swagger UI detected",
    "R_OPENAPI_MARKER": "OpenAPI specification detected",
    "R_REDOC_MARKER": "ReDoc API UI detected",
    "R_OPEN_DOCS": "API documentation is accessible without auth",
    "R_OPEN_API_DATA": "API returned JSON data without auth challenge",
    "R_SENSITIVE_FIELDS": "JSON contains sensitive field names (email, password, token, etc.)",
    "R_GRAPHQL_OPEN": "GraphQL endpoint returned 200 OK",
    "R_SPA_SHELL": "HTML is an empty SPA shell requiring JavaScript",
    "R_RATE_LIMIT_HEADERS": "API rate-limit headers detected",
    "R_CORS_HEADERS": "CORS headers detected",
}


def _escape(s: str | None) -> str:
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_summary_cards(results: list[DomainResult]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        v = r.final_verdict.value
        counts[v] = counts.get(v, 0) + 1

    cards = []
    for verdict, count in sorted(counts.items(), key=lambda x: -x[1]):
        s = _verdict_style(verdict)
        cards.append(f"""
        <div class="card" style="border-color:{s['color']}20; background:{s['bg']}">
          <div class="card-emoji">{s['emoji']}</div>
          <div class="card-count" style="color:{s['color']}">{count}</div>
          <div class="card-label">{verdict}</div>
        </div>""")

    total_open = sum(1 for r in results if r.is_open)
    total_critical = sum(1 for r in results if r.is_critical)
    cards.insert(0, f"""
        <div class="card card-total">
          <div class="card-emoji">🌐</div>
          <div class="card-count">{len(results)}</div>
          <div class="card-label">TOTAL DOMAINS</div>
        </div>""")
    if total_critical:
        cards.insert(1, f"""
        <div class="card" style="border-color:#ef444420; background:rgba(239,68,68,0.15)">
          <div class="card-emoji">🚨</div>
          <div class="card-count" style="color:#ef4444">{total_critical}</div>
          <div class="card-label">CRITICAL</div>
        </div>""")
    return "\n".join(cards)


def _render_table_rows(results: list[DomainResult]) -> str:
    rows = []
    for i, r in enumerate(results):
        s = _verdict_style(r.final_verdict.value)
        tier_badge = f"T{r.tier_reached}"
        manual = "⚑" if r.needs_manual_review else ""
        rows.append(f"""
        <tr class="domain-row" data-verdict="{r.final_verdict.value}" data-service="{r.service_type.value}" data-review="{str(r.needs_manual_review).lower()}" data-tier="{r.tier_reached}" onclick="toggleDetail({i})">
          <td class="domain-cell">{_escape(r.domain)} {manual}</td>
          <td><span class="badge" title="{_escape(r.reasoning or 'No reasoning provided')}" style="color:{s['color']};background:{s['bg']}">{s['emoji']} {r.final_verdict.value}</span></td>
          <td>{_escape(r.service_type.value)}</td>
          <td>
            <div class="confidence-bar-wrap">
              <div class="confidence-bar" style="width:{r.confidence}%;background:{s['color']}"></div>
              <span class="confidence-label">{r.confidence}%</span>
            </div>
          </td>
          <td><span class="tier-badge">{tier_badge}</span></td>
          <td class="signals-cell">{_escape(", ".join(r.signals[:4])) + ("…" if len(r.signals) > 4 else "")}</td>
        </tr>
        <tr class="detail-row" id="detail-{i}" style="display:none">
          <td colspan="6">{_render_detail_panel(r)}</td>
        </tr>""")
    return "\n".join(rows)


def _render_detail_panel(r: DomainResult) -> str:
    sections = []
    s = _verdict_style(r.final_verdict.value)

    # ---- Header + meta strip ------------------------------------------------
    review_badge = (
        '<span style="color:#f59e0b;margin-left:0.5rem" title="Needs manual review">'
        "\u26d1 Manual Review</span>"
    ) if r.needs_manual_review else ""
    meta = (
        f'<span class="meta-chip" style="color:{s["color"]};background:{s["bg"]}">'
        f'{s["emoji"]} {r.final_verdict.value}</span>'
        f'<span class="meta-chip">\U0001f5c2 {r.service_type.value}</span>'
        f'<span class="meta-chip">\U0001f3af {r.confidence}% confidence</span>'
        f'<span class="meta-chip">\u2b06\ufe0f Tier {r.tier_reached} decision</span>'
        f"{review_badge}"
    )
    sections.append(
        f'<div class="detail-header">'
        f"<h3>\U0001f50d Deep Analysis: <span>{_escape(r.domain)}</span></h3>"
        f'<div class="detail-meta">{meta}</div>'
        f"</div>"
    )

    # ---- 1. Final Verdict Reasoning (full-width) -----------------------------
    if r.reasoning:
        sections.append(
            f'<div class="detail-section detail-full">'
            f"<h4>\U0001f3af Final Verdict \u2014 "
            f'<span style="color:{s["color"]}">{r.final_verdict.value}</span></h4>'
            f'<p class="reasoning-text">{_escape(r.reasoning)}</p>'
            f"</div>"
        )

    # ---- 2. Active Discovery — Route Discovery ----------------------------------------
    t0 = r.discovery_output
    if t0 and t0.get("triggered"):
        paths_found = t0.get("paths_found", 0)
        methods = t0.get("methods_used", ["wordlist"])
        disc_paths = t0.get("discovered_paths", [])
        method_str = " + ".join(m.capitalize() for m in methods)
        disc_pills = "".join(
            f'<span class="sig-pill" style="color:#c4b5fd">{_escape(p)}</span>'
            for p in disc_paths[:20]
        ) + (f'<span class="sig-pill" style="opacity:0.6">+{len(disc_paths)-20} more</span>' if len(disc_paths) > 20 else "")
        result_note = (
            f'<div class="escalation-note ok">\U0001f50e {paths_found} viable path{"s" if paths_found != 1 else ""} discovered \u2014 merged into Tier 1 probe set</div>'
            if paths_found > 0
            else '<div class="escalation-note" style="opacity:0.7">\U0001f50e Triggered, but no new viable paths found</div>'
        )
        sections.append(
            f'<div class="detail-section discovery-section">'
            f"<h4>\U0001f50d Active Discovery \u2014 Route Discovery</h4>"
            f'<p><strong>Method:</strong> {_escape(method_str)} &nbsp;|&nbsp; '
            f'<strong>Paths Found:</strong> {paths_found}</p>'
            + (f'<div style="margin:0.5rem 0 0.3rem"><strong style="font-size:0.78rem">Discovered Paths:</strong></div>'
               f'<div class="sig-pills">{disc_pills}</div>'
               if disc_paths else "")
            + result_note
            + "</div>"
        )
    else:
        sections.append(
            '<div class="detail-section discovery-section" style="opacity:0.65">'
            "<h4>\U0001f50d Active Discovery \u2014 Route Discovery</h4>"
            '<p class="skip-note">\u23ed Skipped \u2014 Initial probes had sufficient responses; route discovery not needed.</p>'
            "</div>"
        )

    # ---- 3. HTTP Probe Results -----------------------------------------------
    if r.probe_summary:
        probe_rows = ""
        for path, info in r.probe_summary.items():
            status = info.get("status", "?")
            ct = (info.get("content_type") or "").split(";")[0][:30]
            err = info.get("error")
            redir = f" \u2192 {info.get('final_url', '')}" if info.get("redirect_count", 0) else ""
            cell_class = (
                "probe-ok" if isinstance(status, int) and status < 300
                else "probe-auth" if isinstance(status, int) and status in (401, 403)
                else "probe-err"
            )
            val = f"ERROR: {err[:40]}" if err else f"{status}  {ct}{redir}"
            is_disc = info.get("category") == "discovery_discovered"
            path_badge = (
                '<span class="t0-badge" title="Active Discovery path">\U0001f50e</span> '
                if is_disc else ""
            )
            row_class = "probe-row-discovered" if is_disc else ""
            probe_rows += (
                f'<tr class="{row_class}">'
                f'<td class="probe-path">{path_badge}{_escape(path)}</td>'
                f'<td class="{cell_class}">{_escape(str(val))}</td>'
                f"</tr>"
            )
        sections.append(
            f'<div class="detail-section probe-section">'
            f"<h4>\U0001f4e1 HTTP Probe Results ({len(r.probe_summary)} paths)</h4>"
            f'<div class="probe-table-container">'
            f'<table class="probe-table"><tbody>{probe_rows}</tbody></table></div>'
            f'<p style="font-size:0.72rem;color:var(--muted);margin-top:0.4rem">'
            f"\U0001f50e = Active Discovery path &nbsp;|&nbsp; "
            f'<span class="probe-ok">\u25a0</span> 2xx success &nbsp; '
            f'<span class="probe-auth">\u25a0</span> 401/403 auth &nbsp; '
            f'<span class="probe-err">\u25a0</span> Other</p>'
            f"</div>"
        )

    # ---- 4. Detection Signals ------------------------------------------------
    if r.signals:
        sig_pills = "".join(
            f'<span class="sig-pill" '
            f'title="{_escape(_SIGNAL_DESC.get(sig, "No description available"))}">'
            f"\u2139\ufe0f {_escape(sig)}</span>"
            for sig in r.signals
        )
        sections.append(
            f'<div class="detail-section">'
            f"<h4>\U0001f52c Detection Signals ({len(r.signals)})</h4>"
            f'<div class="sig-pills">{sig_pills}</div>'
            f'<p style="font-size:0.72rem;color:var(--muted);margin-top:0.5rem;'
            f'font-style:italic">Hover a signal for its meaning.</p>'
            f"</div>"
        )

    # ---- 5. Tier 1 — Rule Engine ---------------------------------------------
    t1 = r.tier1_output or {}
    t1_verdict = t1.get("rule_verdict", "\u2014")
    t1_score = t1.get("rule_score", "\u2014")
    t1_needs_llm = t1.get("needs_llm", False)
    t1_reason = t1.get("ambiguity_reason") or ""
    t1_triggered = t1.get("triggered_rules", [])
    triggered_pills = (
        "".join(f'<span class="sig-pill">{_escape(tr)}</span>' for tr in t1_triggered)
        if t1_triggered
        else "<span style='color:var(--muted);font-style:italic'>None</span>"
    )
    score_color = "#22c55e" if isinstance(t1_score, int) and t1_score >= 65 else "#f59e0b"
    esc_note = (
        f'<div class="escalation-note">\u2b06\ufe0f Escalated to Tier 2 \u2014 {_escape(t1_reason)}</div>'
        if t1_needs_llm
        else '<div class="escalation-note ok">\u2705 High confidence \u2014 no escalation needed</div>'
    )
    sections.append(
        f'<div class="detail-section tier1-section">'
        f"<h4>\u2699\ufe0f Tier 1 \u2014 Rule Engine</h4>"
        f"<p><strong>Verdict:</strong> {_escape(t1_verdict)} &nbsp;|&nbsp; "
        f'<strong>Score:</strong> <span style="color:{score_color};font-weight:700">'
        f"{t1_score}/100</span></p>"
        f'<div style="margin:0.5rem 0 0.3rem">'
        f'<strong style="font-size:0.78rem">Triggered Rules:</strong></div>'
        f'<div class="sig-pills">{triggered_pills}</div>'
        f"{esc_note}"
        f"</div>"
    )

    # ---- 6. Tier 2 — Static Analysis (LLM) ----------------------------------
    if r.tier2_output:
        t2 = r.tier2_output
        t2_verdict = t2.get("verdict", "\u2014")
        t2_conf = t2.get("confidence", "\u2014")
        mechs = t2.get("auth_mechanisms_detected", [])
        mech_pills = (
            "".join(f'<span class="mech-pill">{_escape(m)}</span>' for m in mechs)
            if mechs
            else "<span style='color:var(--muted);font-style:italic'>None detected</span>"
        )
        if t2.get("needs_browser_escalation"):
            reason2 = t2.get("browser_escalation_reason") or "JS execution required."
            esc2 = (
                f'<div class="escalation-note">\u2b06\ufe0f Escalated to Tier 3 \u2014 {_escape(reason2)}</div>'
            )
        else:
            esc2 = (
                '<div class="escalation-note ok">'
                "\u2705 Sufficient evidence \u2014 no browser escalation</div>"
            )
        sections.append(
            f'<div class="detail-section tier2-section">'
            f"<h4>\U0001f9e0 Tier 2 \u2014 Static Analysis "
            f'<span class="tier-label">(LLM)</span></h4>'
            f"<p><strong>Verdict:</strong> {_escape(t2_verdict)} ({t2_conf}%)</p>"
            f'<div style="margin:0.5rem 0 0.3rem">'
            f'<strong style="font-size:0.78rem">Auth Mechanisms Detected:</strong></div>'
            f'<div class="sig-pills">{mech_pills}</div>'
            + (
                f'<p style="margin-top:0.5rem"><strong>Visual Observation:</strong> '
                f'{_escape(t2.get("visual_evidence", ""))}</p>'
                if t2.get("visual_evidence") else ""
            )
            + (
                f'<p style="margin-top:0.5rem"><strong>LLM Reasoning:</strong> '
                f'{_escape(t2.get("reasoning", ""))}</p>'
            )
            + esc2
            + "</div>"
        )
    else:
        needs_llm = (r.tier1_output or {}).get("needs_llm", False)
        skip_msg = (
            "Service is unreachable or returned no usable content."
            if needs_llm
            else "High-confidence Tier 1 verdict \u2014 LLM analysis not required."
        )
        sections.append(
            f'<div class="detail-section tier2-skipped">'
            f"<h4>\U0001f9e0 Tier 2 \u2014 Static Analysis "
            f'<span class="tier-label">(LLM)</span></h4>'
            f'<p class="skip-note">\u23ed Skipped \u2014 {skip_msg}</p>'
            f"</div>"
        )

    # ---- 7. Tier 3 — Browser Agent (Hermes) ---------------------------------
    if r.tier3_output:
        t3 = r.tier3_output
        t3_verdict = t3.get("verdict", "\u2014")
        t3_conf = t3.get("confidence", "\u2014")
        steps = t3.get("interaction_steps", [])
        steps_html = ""
        if steps:
            items = "".join(f"<li>{_escape(st)}</li>" for st in steps)
            steps_html = (
                f'<div style="margin-top:0.6rem">'
                f'<strong style="font-size:0.78rem">Browser Steps ({len(steps)}):</strong>'
                f'<ol class="step-list">{items}</ol></div>'
            )
        shots = t3.get("screenshots", [])
        screenshot_html = ""
        for ss in shots:
            if ss:
                ss_str = str(ss)
                if ss_str.startswith("http://") or ss_str.startswith("https://"):
                    screenshot_html += (
                        f'<a href="{_escape(ss_str)}" target="_blank" '
                        f'title="Open full size">'
                        f'<img class="screenshot" src="{_escape(ss_str)}" '
                        f'alt="screenshot" loading="lazy" /></a>'
                    )
                else:
                    screenshot_html += (
                        f'<span class="screenshot-ref">\U0001f4f7 {_escape(ss_str)}</span>'
                    )
        shots_section = ""
        if screenshot_html:
            n = len(shots)
            shots_section = (
                f'<div style="margin-top:0.8rem">'
                f'<strong style="font-size:0.78rem">\U0001f4f8 Visual Evidence '
                f"({n} screenshot{'s' if n != 1 else ''}):</strong>"
                f'<div class="screenshots">{screenshot_html}</div>'
                f"</div>"
            )
        sections.append(
            f'<div class="detail-section tier3-section">'
            f"<h4>\U0001f5a5\ufe0f Tier 3 \u2014 Browser Agent "
            f'<span class="tier-label">(Hermes)</span></h4>'
            f"<p><strong>Verdict:</strong> {_escape(t3_verdict)} ({t3_conf}%)</p>"
            + (
                f'<p style="margin-top:0.4rem"><strong>Visual Evidence:</strong> '
                f'{_escape(t3.get("visual_evidence", ""))}</p>'
                if t3.get("visual_evidence") else ""
            )
            + f'<p style="margin-top:0.4rem"><strong>Reasoning:</strong> {_escape(t3.get("reasoning", ""))}</p>'
            + steps_html
            + shots_section
            + "</div>"
        )
    else:
        if r.tier_reached == 1:
            skip_msg = "High-confidence Tier 1 verdict \u2014 LLM and browser analysis skipped."
        elif r.tier_reached == 2 and r.tier2_output and not r.tier2_output.get("needs_browser_escalation"):
            skip_msg = "Tier 2 reached a confident verdict \u2014 no browser escalation required."
        else:
            skip_msg = "Service returned no viable content \u2014 browser agent skipped."
        sections.append(
            f'<div class="detail-section tier3-skipped">'
            f"<h4>\U0001f5a5\ufe0f Tier 3 \u2014 Browser Agent "
            f'<span class="tier-label">(Hermes)</span></h4>'
            f'<p class="skip-note">\u23ed Skipped \u2014 {skip_msg}</p>'
            f"</div>"
        )

    return f'<div class="detail-panel">{" ".join(sections)}</div>'


def generate_report(results: list[DomainResult], output_path: Path) -> None:
    """
    Render the HTML report for ``results`` and write it to ``output_path``.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary_cards = _render_summary_cards(results)
    table_rows = _render_table_rows(results)
    verdict_options = "\n".join(
        f'<option value="{v}">{v}</option>'
        for v in sorted(set(r.final_verdict.value for r in results))
    )
    service_options = "\n".join(
        f'<option value="{s}">{s}</option>'
        for s in sorted(set(r.service_type.value for r in results))
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Auth Audit Report — {generated_at}</title>
<meta name="description" content="Authentication detection pipeline audit report generated by auth-audit." />
<style>
  /* ── Reset & base ───────────────────────────────────── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg: #0a0d1a;
    --surface: rgba(255,255,255,0.03);
    --border: rgba(255,255,255,0.08);
    --text: #e2e8f0;
    --muted: #64748b;
    --accent: #6366f1;
    --font: 'Inter', system-ui, sans-serif;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }}
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

  /* ── Header ─────────────────────────────────────────── */
  .header {{
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    padding: 2rem 2.5rem;
    display: flex; align-items: center; justify-content: space-between;
    border-bottom: 1px solid var(--border);
  }}
  .header-title h1 {{ font-size: 1.6rem; font-weight: 700; letter-spacing: -0.5px; }}
  .header-title h1 span {{ color: var(--accent); }}
  .header-meta {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem; }}
  .header-badge {{ background: rgba(99,102,241,0.2); border: 1px solid rgba(99,102,241,0.4);
    color: #a5b4fc; padding: 0.4rem 1rem; border-radius: 2rem; font-size: 0.8rem; font-weight: 500; }}

  /* ── Summary cards ──────────────────────────────────── */
  .cards-row {{
    display: flex; flex-wrap: wrap; gap: 1rem;
    padding: 1.5rem 2.5rem; background: rgba(255,255,255,0.01);
    border-bottom: 1px solid var(--border);
  }}
  .card {{
    flex: 1; min-width: 120px; max-width: 180px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 1rem; padding: 1.2rem 1rem; text-align: center;
    backdrop-filter: blur(10px); transition: transform .2s, box-shadow .2s;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 30px rgba(0,0,0,0.4); }}
  .card-total {{ border-color: rgba(99,102,241,0.3); background: rgba(99,102,241,0.08); }}
  .card-emoji {{ font-size: 1.6rem; margin-bottom: 0.4rem; }}
  .card-count {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
  .card-label {{ font-size: 0.65rem; font-weight: 600; letter-spacing: 1px; color: var(--muted); margin-top: 0.3rem; text-transform: uppercase; }}

  /* ── Controls ───────────────────────────────────────── */
  .controls {{
    display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;
    padding: 1rem 2.5rem; border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,0.01);
  }}
  .controls input, .controls select {{
    background: rgba(255,255,255,0.05); border: 1px solid var(--border);
    color: var(--text); padding: 0.5rem 1rem; border-radius: 0.5rem;
    font-size: 0.85rem; outline: none; transition: border-color .2s;
  }}
  .controls input:focus, .controls select:focus {{ border-color: var(--accent); }}
  .controls input[type="text"] {{ width: 220px; }}
  .controls label {{ font-size: 0.8rem; color: var(--muted); display: flex; align-items: center; gap: 0.4rem; cursor: pointer; }}
  .controls input[type="checkbox"] {{ width: 1.1rem; height: 1.1rem; cursor: pointer; }}
  .count-label {{ margin-left: auto; font-size: 0.8rem; color: var(--muted); }}

  /* ── Table ──────────────────────────────────────────── */
  .table-wrap {{ padding: 1.5rem 2.5rem; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{
    text-align: left; padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    color: var(--muted); font-weight: 600; font-size: 0.75rem;
    letter-spacing: 0.5px; text-transform: uppercase;
    cursor: pointer; user-select: none;
  }}
  th:hover {{ color: var(--text); }}
  .domain-row {{
    cursor: pointer; transition: background .15s;
    border-bottom: 1px solid rgba(255,255,255,0.03);
  }}
  .domain-row:hover {{ background: rgba(255,255,255,0.04); }}
  td {{ padding: 0.8rem 1rem; vertical-align: middle; }}
  .domain-cell {{ font-weight: 500; font-family: 'SF Mono', monospace; font-size: 0.85rem; }}
  .badge {{
    display: inline-flex; align-items: center; gap: 0.3rem;
    padding: 0.25rem 0.65rem; border-radius: 1rem;
    font-size: 0.75rem; font-weight: 600; white-space: nowrap;
  }}
  .tier-badge {{
    background: rgba(99,102,241,0.15); color: #a5b4fc;
    padding: 0.2rem 0.5rem; border-radius: 0.4rem;
    font-size: 0.7rem; font-weight: 700;
  }}
  .signals-cell {{ color: var(--muted); font-size: 0.8rem; font-family: monospace; }}
  .confidence-bar-wrap {{ display: flex; align-items: center; gap: 0.5rem; }}
  .confidence-bar {{
    height: 6px; border-radius: 3px;
    min-width: 4px; transition: width .3s;
  }}
  .confidence-label {{ font-size: 0.8rem; color: var(--muted); white-space: nowrap; }}

  /* ── Detail panel ───────────────────────────────────── */
  .detail-row td {{ padding: 0; background: rgba(0,0,0,0.3); }}
  .detail-panel {{
    padding: 1.5rem 2rem; display: flex; flex-wrap: wrap; gap: 1rem;
    border-top: 2px solid var(--accent); animation: slideDown .2s ease;
  }}
  @keyframes slideDown {{ from {{ opacity:0; transform:translateY(-6px) }} to {{ opacity:1; transform:none }} }}
  .detail-section {{
    flex: 1; min-width: 280px;
    background: rgba(255,255,255,0.03); border: 1px solid var(--border);
    border-radius: 0.75rem; padding: 1rem;
  }}
  .detail-section h4 {{ font-size: 0.8rem; color: var(--muted); margin-bottom: 0.6rem; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; }}
  .reasoning-text {{ font-size: 0.875rem; line-height: 1.6; color: var(--text); }}
  .sig-pills {{ display: flex; flex-wrap: wrap; gap: 0.4rem; }}
  .sig-pill {{
    background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.2);
    color: #a5b4fc; padding: 0.2rem 0.5rem; border-radius: 0.4rem;
    font-size: 0.7rem; font-family: monospace;
  }}
  .evidence-list {{ padding-left: 1.2rem; font-size: 0.85rem; color: var(--muted); }}
  .evidence-list li {{ margin-bottom: 0.3rem; }}
  .no-evidence {{ font-size: 0.8rem; color: var(--muted); font-style: italic; }}
  /* ── Tier section colour coding ─────────────────────────────────── */
  .discovery-section {{ border-left: 3px solid #a78bfa; }}
  .tier1-section {{ border-left: 3px solid #94a3b8; }}
  .tier2-section {{ border-left: 3px solid #6366f1; }}
  .tier3-section {{ border-left: 3px solid #22c55e; }}
  .tier2-skipped, .tier3-skipped {{ border-left: 3px solid #475569; opacity: 0.7; }}
  .tier1-section p, .tier2-section p, .tier3-section p,
  .tier2-skipped p, .tier3-skipped p {{ font-size: 0.85rem; margin-bottom: 0.5rem; line-height: 1.5; }}
  .tier-label {{ font-size: 0.72rem; font-weight: 400; color: var(--muted); letter-spacing: 0; text-transform: none; }}
  /* full-width detail section */
  .detail-full {{ flex: 1 1 100%; width: 100%; min-width: unset; }}
  /* meta strip below header */
  .detail-meta {{ display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.6rem; }}
  .meta-chip {{
    display: inline-flex; align-items: center; gap: 0.25rem;
    padding: 0.2rem 0.6rem; border-radius: 1rem; font-size: 0.72rem;
    font-weight: 600; background: rgba(255,255,255,0.06); border: 1px solid var(--border);
    color: var(--text);
  }}
  /* auth mechanism pills (green tint) */
  .mech-pill {{
    background: rgba(34,197,94,0.08); border: 1px solid rgba(34,197,94,0.25);
    color: #86efac; padding: 0.2rem 0.5rem; border-radius: 0.4rem;
    font-size: 0.72rem; font-family: monospace;
  }}
  /* escalation annotations */
  .escalation-note {{
    margin-top: 0.6rem; padding: 0.35rem 0.7rem; border-radius: 0.4rem;
    font-size: 0.78rem; background: rgba(245,158,11,0.08);
    border: 1px solid rgba(245,158,11,0.2); color: #fbbf24;
  }}
  .escalation-note.ok {{
    background: rgba(34,197,94,0.08); border-color: rgba(34,197,94,0.2); color: #86efac;
  }}
  .skip-note {{ color: var(--muted); font-style: italic; }}

  .step-list {{ padding-left: 1.2rem; font-size: 0.85rem; color: var(--muted); margin-top: 0.5rem; }}
  .screenshot {{ max-width: 100%; border-radius: 0.5rem; margin-top: 0.75rem; border: 1px solid var(--border); cursor: pointer; transition: opacity .2s, transform .2s; display: block; }}
  .screenshot:hover {{ opacity: 0.85; transform: scale(1.01); }}
  .screenshot-ref {{
    display: inline-flex; align-items: center; gap: 0.3rem;
    background: rgba(255,255,255,0.05); border: 1px solid var(--border);
    padding: 0.25rem 0.6rem; border-radius: 0.4rem;
    font-size: 0.75rem; font-family: monospace; color: var(--muted);
    margin: 0.25rem 0.25rem 0 0;
  }}
  .probe-table-container {{
    max-height: 250px; overflow-y: auto; 
    border: 1px solid rgba(255,255,255,0.05); border-radius: 4px;
    margin-top: 0.25rem;
  }}
  .probe-table-container::-webkit-scrollbar {{ width: 6px; }}
  .probe-table-container::-webkit-scrollbar-track {{ background: rgba(0,0,0,0.1); }}
  .probe-table-container::-webkit-scrollbar-thumb {{ background: rgba(255,255,255,0.1); border-radius: 3px; }}
  .probe-table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
  .probe-table td {{ padding: 0.2rem 0.4rem; border-bottom: 1px solid rgba(255,255,255,0.04); }}
  .probe-path {{ font-family: monospace; color: var(--muted); width: 40%; }}
  .probe-ok {{ color: #22c55e; }}
  .probe-auth {{ color: #f59e0b; }}
  .probe-err {{ color: #94a3b8; }}
  .probe-more {{ color: var(--muted); font-style: italic; text-align: center; padding-top: 0.3rem; }}
  .probe-row-discovered {{ background: rgba(99,102,241,0.06); }}
  .t0-badge {{ font-size: 0.65rem; opacity: 0.7; cursor: help; }}
  
  /* ── Info section ───────────────────────────────────── */
  .info-section {{
    display: flex; gap: 2rem; padding: 1.5rem 2.5rem; flex-wrap: wrap;
    background: rgba(255,255,255,0.01); border-bottom: 1px solid var(--border);
  }}
  .info-block {{ flex: 1; min-width: 300px; }}
  .info-block h3 {{ font-size: 0.85rem; color: var(--text); margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
  .legend-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 0.8rem; }}
  .legend-item {{ font-size: 0.8rem; color: var(--muted); display: flex; align-items: center; gap: 0.6rem; }}
  .legend-item .badge {{ width: 140px; justify-content: center; }}
  .workflow-list {{ list-style: none; padding: 0; display: flex; flex-direction: column; gap: 0.75rem; }}
  .workflow-list li {{ font-size: 0.85rem; color: var(--muted); display: flex; align-items: center; gap: 0.6rem; }}
  .workflow-list li strong {{ color: var(--text); font-weight: 500; }}
  
  /* Detail panel header */
  .detail-header {{ width: 100%; margin-bottom: 0.5rem; padding-bottom: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.05); }}
  .detail-header h3 {{ font-size: 1.1rem; font-weight: 600; color: var(--accent); display: flex; align-items: center; gap: 0.5rem; }}
  .detail-header h3 span {{ color: var(--text); font-family: 'SF Mono', monospace; font-weight: 500; }}

  /* ── Footer ─────────────────────────────────────────── */
  .footer {{
    text-align: center; padding: 2rem;
    font-size: 0.75rem; color: var(--muted);
    border-top: 1px solid var(--border);
  }}

  /* ── Hidden ─────────────────────────────────────────── */
  .hidden {{ display: none !important; }}
</style>
</head>
<body>

<header class="header">
  <div class="header-title">
    <h1>🔐 <span>Auth</span>Audit Report</h1>
    <div class="header-meta">Generated: {generated_at} &nbsp;|&nbsp; auth-audit pipeline v0.1</div>
  </div>
  <div class="header-badge">Security Audit</div>
</header>

<section class="cards-row">
  {summary_cards}
</section>

<section class="info-section">
  <div class="info-block legend-block">
    <h3>📖 Verdict Legend</h3>
    <div class="legend-grid">
      <div class="legend-item"><span class="badge" style="color:#22c55e;background:rgba(34,197,94,0.15)">🔒 PROTECTED</span> Strong auth; login required</div>
      <div class="legend-item"><span class="badge" style="color:#f59e0b;background:rgba(245,158,11,0.15)">⚠️ PARTIAL</span> Some paths protected, others open</div>
      <div class="legend-item"><span class="badge" style="color:#3b82f6;background:rgba(59,130,246,0.15)">🔓 OPEN</span> Public content, no auth required</div>
      <div class="legend-item"><span class="badge" style="color:#f97316;background:rgba(249,115,22,0.15)">🔓 OPEN_API</span> API reachable without auth</div>
      <div class="legend-item"><span class="badge" style="color:#ef4444;background:rgba(239,68,68,0.15)">🚨 OPEN_API_CRITICAL</span> API exposing sensitive data</div>
      <div class="legend-item"><span class="badge" style="color:#a78bfa;background:rgba(167,139,250,0.15)">📄 OPEN_DOCS</span> Swagger/OpenAPI exposed</div>
      <div class="legend-item"><span class="badge" style="color:#6b7280;background:rgba(107,114,128,0.15)">💀 UNREACHABLE</span> Domain is offline or blocked</div>
      <div class="legend-item"><span class="badge" style="color:#94a3b8;background:rgba(148,163,184,0.15)">❓ UNKNOWN</span> Needs manual review</div>
    </div>
  </div>
  <div class="info-block workflow-block">
    <h3>⚙️ Escalation Workflow</h3>
    <ul class="workflow-list">
      <li><span class="tier-badge">T0</span> <strong>Active Discovery:</strong> Triggered on high 404s to brute-force API/Auth paths.</li>
      <li><span class="tier-badge">T1</span> <strong>Rule Engine:</strong> Fast async HTTP probing & deterministic signal extraction.</li>
      <li><span class="tier-badge">T2</span> <strong>LLM Analysis:</strong> Escalate if ambiguous. OpenAI-compatible LLM analyzes HTML/DOM.</li>
      <li><span class="tier-badge">T3</span> <strong>Browser Agent:</strong> Escalate if SPA shell. Hermes agent runs JS and navigates.</li>
    </ul>
  </div>
</section>

<section class="controls">
  <label>🔍</label>
  <input type="text" id="search" placeholder="Filter domains..." oninput="filterTable()" />
  <select id="filterVerdict" onchange="filterTable()">
    <option value="">All verdicts</option>
    {verdict_options}
  </select>
  <select id="filterService" onchange="filterTable()">
    <option value="">All service types</option>
    {service_options}
  </select>
  <select id="filterTier" onchange="filterTable()">
    <option value="">All tiers</option>
    <option value="1">Tier 1 (Rule Engine)</option>
    <option value="2">Tier 2 (LLM Analysis)</option>
    <option value="3">Tier 3 (Browser Agent)</option>
  </select>
  <label style="margin-left: 0.5rem; color: #f59e0b; font-weight: 500;">
    <input type="checkbox" id="filterReview" onchange="filterTable()" />
    ⚑ Needs Review
  </label>
  <span class="count-label" id="countLabel">{len(results)} domains</span>
</section>

<div class="table-wrap">
  <table id="domainTable">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Domain ↕</th>
        <th onclick="sortTable(1)">Verdict ↕</th>
        <th onclick="sortTable(2)">Service Type ↕</th>
        <th onclick="sortTable(3)">Confidence ↕</th>
        <th>Tier</th>
        <th>Signals</th>
      </tr>
    </thead>
    <tbody id="tableBody">
      {table_rows}
    </tbody>
  </table>
</div>

<footer class="footer">
  auth-audit — Authentication Detection Pipeline &nbsp;|&nbsp; {generated_at}
</footer>

<script>
  // Toggle detail rows
  function toggleDetail(i) {{
    const row = document.getElementById('detail-' + i);
    row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
  }}

  // Filter
  function filterTable() {{
    const search = document.getElementById('search').value.toLowerCase();
    const verdict = document.getElementById('filterVerdict').value;
    const service = document.getElementById('filterService').value;
    const tier = document.getElementById('filterTier').value;
    const reviewOnly = document.getElementById('filterReview').checked;
    
    const rows = document.querySelectorAll('.domain-row');
    let visible = 0;
    rows.forEach(row => {{
      const dom = row.querySelector('.domain-cell').textContent.toLowerCase();
      const v = row.dataset.verdict;
      const s = row.dataset.service;
      const t = row.dataset.tier;
      const r = row.dataset.review === "true";
      
      const show = dom.includes(search) 
                   && (!verdict || v === verdict) 
                   && (!service || s === service)
                   && (!tier || t === tier)
                   && (!reviewOnly || r);
                   
      row.classList.toggle('hidden', !show);
      const id = row.getAttribute('onclick').match(/\\d+/)[0];
      const detail = document.getElementById('detail-' + id);
      if (detail) detail.classList.toggle('hidden', !show);
      if (show) visible++;
    }});
    document.getElementById('countLabel').textContent = visible + ' domain' + (visible !== 1 ? 's' : '');
  }}

  // Sort
  let sortDir = {{}};
  function sortTable(col) {{
    const tbody = document.getElementById('tableBody');
    const rows = Array.from(tbody.querySelectorAll('.domain-row'));
    const dir = sortDir[col] = -(sortDir[col] || 1);
    rows.sort((a, b) => {{
      const at = a.cells[col].textContent.trim();
      const bt = b.cells[col].textContent.trim();
      const an = parseFloat(at), bn = parseFloat(bt);
      if (!isNaN(an) && !isNaN(bn)) return (an - bn) * dir;
      return at.localeCompare(bt) * dir;
    }});
    rows.forEach(row => {{
      const id = row.getAttribute('onclick').match(/\\d+/)[0];
      const detail = document.getElementById('detail-' + id);
      tbody.appendChild(row);
      if (detail) tbody.appendChild(detail);
    }});
  }}
</script>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s", output_path)
