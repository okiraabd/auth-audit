
import pathlib

src = pathlib.Path("src/reporting/html_report.py").read_text(encoding="utf-8")

new_func = '''def _render_detail_panel(r: DomainResult) -> str:
    sections = []
    s = _verdict_style(r.final_verdict.value)

    # ---- Header + meta strip ------------------------------------------------
    review_badge = (
        '<span style="color:#f59e0b;margin-left:0.5rem" title="Needs manual review">'
        "\\u26d1 Manual Review</span>"
    ) if r.needs_manual_review else ""
    meta = (
        f'<span class="meta-chip" style="color:{s["color"]};background:{s["bg"]}">'
        f'{s["emoji"]} {r.final_verdict.value}</span>'
        f'<span class="meta-chip">\\U0001f5c2 {r.service_type.value}</span>'
        f'<span class="meta-chip">\\U0001f3af {r.confidence}% confidence</span>'
        f'<span class="meta-chip">\\u2b06\\ufe0f Tier {r.tier_reached} decision</span>'
        f"{review_badge}"
    )
    sections.append(
        f'<div class="detail-header">'
        f"<h3>\\U0001f50d Deep Analysis: <span>{_escape(r.domain)}</span></h3>"
        f'<div class="detail-meta">{meta}</div>'
        f"</div>"
    )

    # ---- 1. Final Verdict Reasoning (full-width) -----------------------------
    if r.reasoning:
        sections.append(
            f'<div class="detail-section detail-full">'
            f"<h4>\\U0001f3af Final Verdict \\u2014 "
            f'<span style="color:{s["color"]}">{r.final_verdict.value}</span></h4>'
            f'<p class="reasoning-text">{_escape(r.reasoning)}</p>'
            f"</div>"
        )

    # ---- 2. Detection Signals ------------------------------------------------
    if r.signals:
        sig_pills = "".join(
            f'<span class="sig-pill" '
            f'title="{_escape(_SIGNAL_DESC.get(sig, "No description available"))}">'
            f"\\u2139\\ufe0f {_escape(sig)}</span>"
            for sig in r.signals
        )
        sections.append(
            f'<div class="detail-section">'
            f"<h4>\\U0001f52c Detection Signals ({len(r.signals)})</h4>"
            f'<div class="sig-pills">{sig_pills}</div>'
            f'<p style="font-size:0.72rem;color:var(--muted);margin-top:0.5rem;'
            f'font-style:italic">Hover a signal for its meaning.</p>'
            f"</div>"
        )

    # ---- 3. Tier 1 — Rule Engine ---------------------------------------------
    t1 = r.tier1_output or {}
    t1_verdict = t1.get("rule_verdict", "\\u2014")
    t1_score = t1.get("rule_score", "\\u2014")
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
        f'<div class="escalation-note">\\u2b06\\ufe0f Escalated to Tier 2 \\u2014 {_escape(t1_reason)}</div>'
        if t1_needs_llm
        else '<div class="escalation-note ok">\\u2705 High confidence \\u2014 no escalation needed</div>'
    )
    sections.append(
        f'<div class="detail-section tier1-section">'
        f"<h4>\\u2699\\ufe0f Tier 1 \\u2014 Rule Engine</h4>"
        f"<p><strong>Verdict:</strong> {_escape(t1_verdict)} &nbsp;|&nbsp; "
        f'<strong>Score:</strong> <span style="color:{score_color};font-weight:700">'
        f"{t1_score}/100</span></p>"
        f'<div style="margin:0.5rem 0 0.3rem">'
        f'<strong style="font-size:0.78rem">Triggered Rules:</strong></div>'
        f'<div class="sig-pills">{triggered_pills}</div>'
        f"{esc_note}"
        f"</div>"
    )

    # ---- 4. HTTP Probe Results -----------------------------------------------
    if r.probe_summary:
        probe_rows = ""
        for path, info in r.probe_summary.items():
            status = info.get("status", "?")
            ct = (info.get("content_type") or "").split(";")[0][:30]
            err = info.get("error")
            redir = f" \\u2192 {info.get('final_url', '')}" if info.get("redirect_count", 0) else ""
            cell_class = (
                "probe-ok" if isinstance(status, int) and status < 300
                else "probe-auth" if isinstance(status, int) and status in (401, 403)
                else "probe-err"
            )
            val = f"ERROR: {err[:40]}" if err else f"{status}  {ct}{redir}"
            is_disc = info.get("category") == "discovery_discovered"
            path_badge = (
                '<span class="t0-badge" title="Active Discovery path">\\U0001f50e</span> '
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
            f"<h4>\\U0001f4e1 HTTP Probe Results ({len(r.probe_summary)} paths)</h4>"
            f'<div class="probe-table-container">'
            f'<table class="probe-table"><tbody>{probe_rows}</tbody></table></div>'
            f'<p style="font-size:0.72rem;color:var(--muted);margin-top:0.4rem">'
            f"\\U0001f50e = Active Discovery path &nbsp;|&nbsp; "
            f'<span class="probe-ok">\\u25a0</span> 2xx success &nbsp; '
            f'<span class="probe-auth">\\u25a0</span> 401/403 auth &nbsp; '
            f'<span class="probe-err">\\u25a0</span> Other</p>'
            f"</div>"
        )

    # ---- 5. Tier 2 — Static Analysis (LLM) ----------------------------------
    if r.tier2_output:
        t2 = r.tier2_output
        t2_verdict = t2.get("verdict", "\\u2014")
        t2_conf = t2.get("confidence", "\\u2014")
        mechs = t2.get("auth_mechanisms_detected", [])
        mech_pills = (
            "".join(f'<span class="mech-pill">{_escape(m)}</span>' for m in mechs)
            if mechs
            else "<span style='color:var(--muted);font-style:italic'>None detected</span>"
        )
        if t2.get("needs_browser_escalation"):
            reason2 = t2.get("browser_escalation_reason") or "JS execution required."
            esc2 = (
                f'<div class="escalation-note">\\u2b06\\ufe0f Escalated to Tier 3 \\u2014 {_escape(reason2)}</div>'
            )
        else:
            esc2 = (
                '<div class="escalation-note ok">'
                "\\u2705 Sufficient evidence \\u2014 no browser escalation</div>"
            )
        sections.append(
            f'<div class="detail-section tier2-section">'
            f"<h4>\\U0001f9e0 Tier 2 \\u2014 Static Analysis "
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
            else "High-confidence Tier 1 verdict \\u2014 LLM analysis not required."
        )
        sections.append(
            f'<div class="detail-section tier2-skipped">'
            f"<h4>\\U0001f9e0 Tier 2 \\u2014 Static Analysis "
            f'<span class="tier-label">(LLM)</span></h4>'
            f'<p class="skip-note">\\u23ed Skipped \\u2014 {skip_msg}</p>'
            f"</div>"
        )

    # ---- 6. Tier 3 — Browser Agent (Hermes) ---------------------------------
    if r.tier3_output:
        t3 = r.tier3_output
        t3_verdict = t3.get("verdict", "\\u2014")
        t3_conf = t3.get("confidence", "\\u2014")
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
                        f'<span class="screenshot-ref">\\U0001f4f7 {_escape(ss_str)}</span>'
                    )
        shots_section = ""
        if screenshot_html:
            n = len(shots)
            shots_section = (
                f'<div style="margin-top:0.8rem">'
                f'<strong style="font-size:0.78rem">\\U0001f4f8 Visual Evidence '
                f"({n} screenshot{'s' if n != 1 else ''}):</strong>"
                f'<div class="screenshots">{screenshot_html}</div>'
                f"</div>"
            )
        sections.append(
            f'<div class="detail-section tier3-section">'
            f"<h4>\\U0001f5a5\\ufe0f Tier 3 \\u2014 Browser Agent "
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
            skip_msg = "High-confidence Tier 1 verdict \\u2014 LLM and browser analysis skipped."
        elif r.tier_reached == 2 and r.tier2_output and not r.tier2_output.get("needs_browser_escalation"):
            skip_msg = "Tier 2 reached a confident verdict \\u2014 no browser escalation required."
        else:
            skip_msg = "Service returned no viable content \\u2014 browser agent skipped."
        sections.append(
            f'<div class="detail-section tier3-skipped">'
            f"<h4>\\U0001f5a5\\ufe0f Tier 3 \\u2014 Browser Agent "
            f'<span class="tier-label">(Hermes)</span></h4>'
            f'<p class="skip-note">\\u23ed Skipped \\u2014 {skip_msg}</p>'
            f"</div>"
        )

    return f'<div class="detail-panel">{" ".join(sections)}</div>'

'''

start = src.find("def _render_detail_panel(r: DomainResult)")
end = src.find("def generate_report(results: list[DomainResult]")
new_src = src[:start] + new_func + "\n" + src[end:]
pathlib.Path("src/reporting/html_report.py").write_text(new_src, encoding="utf-8")
print("OK, total lines:", new_src.count("\n"))
