"""
tier2/html_summarizer.py — HTML content condenser for LLM input preparation.

Transforms raw HTML into a compact, structured plain-text block that surfaces
the auth-relevant signals without sending the full HTML (which may be 50KB+).

Extraction priority:
  1. <title>
  2. <meta name="description">
  3. <h1> through <h3>
  4. <form> elements with their <input> fields and submit buttons
  5. Navigation links (<nav>, <header> anchors)
  6. Auth-related text snippets in body
  7. SPA / framework detection markers

The output is truncated to ``max_chars`` before returning, with priority
sections placed at the top so the LLM always sees the most important content
even if truncation occurs.

Uses BeautifulSoup4 + lxml for robust HTML parsing. Falls back to html.parser
if lxml is not available.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Auth-related keywords to surface from body text
_AUTH_KEYWORDS: tuple[str, ...] = (
    "sign in",
    "log in",
    "login",
    "logout",
    "log out",
    "sign out",
    "forgot password",
    "reset password",
    "create account",
    "register",
    "username",
    "password",
    "remember me",
    "two-factor",
    "2fa",
    "otp",
    "authentication",
    "authoriz",
    "unauthoriz",
    "access denied",
    "permission denied",
    "session expired",
    "please sign",
    "please log",
)

# SPA / framework signals in raw HTML
_SPA_MARKERS: dict[str, str] = {
    'id="root"': "React/generic SPA shell",
    'id="app"': "Vue/generic SPA shell",
    'data-reactroot': "React SSR marker",
    "__next_router": "Next.js",
    "__nuxt__": "Nuxt.js",
    "window.__INITIAL_STATE__": "Redux/Vuex state injection",
    "ng-version": "Angular",
    "data-ng-app": "AngularJS",
    "svelte": "Svelte",
}


def summarize_html(raw_html: str, max_chars: int = 4000) -> str:
    """
    Extract and condense the most auth-relevant content from raw HTML.

    Args:
        raw_html:  Raw HTML string from a probe response body.
        max_chars: Maximum character length of the returned summary.
                   Defaults to ``config.llm_max_html_chars``.

    Returns:
        A structured plain-text summary ready to embed in an LLM prompt.
        Returns an empty string if parsing fails or the input is empty.
    """
    if not raw_html or not raw_html.strip():
        return ""

    try:
        return _build_summary(raw_html, max_chars)
    except Exception as exc:
        logger.debug("HTML summarization failed: %s", exc, exc_info=True)
        # Fallback: return a truncated raw strip of text
        stripped = re.sub(r"<[^>]+>", " ", raw_html)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        return stripped[:max_chars]


def _build_summary(raw_html: str, max_chars: int) -> str:
    """Build the structured summary using BeautifulSoup4."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:  # pragma: no cover
        raise ImportError("beautifulsoup4 is required for HTML summarization.")

    # Try lxml first (faster), fall back to html.parser
    try:
        soup = BeautifulSoup(raw_html, "lxml")
    except Exception:
        soup = BeautifulSoup(raw_html, "html.parser")

    sections: list[str] = []

    # ---- 1. Title ----
    title_tag = soup.find("title")
    if title_tag and title_tag.get_text(strip=True):
        sections.append(f"TITLE: {title_tag.get_text(strip=True)[:200]}")

    # ---- 2. Meta description ----
    meta_desc = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    if meta_desc and meta_desc.get("content"):
        sections.append(f"META_DESCRIPTION: {str(meta_desc['content'])[:300]}")

    # ---- 3. Headings h1-h3 ----
    headings = []
    for tag in soup.find_all(["h1", "h2", "h3"]):
        text = tag.get_text(separator=" ", strip=True)
        if text:
            headings.append(f"  [{tag.name.upper()}] {text[:120]}")
    if headings:
        sections.append("HEADINGS:\n" + "\n".join(headings[:10]))

    # ---- 4. Forms + inputs ----
    forms = soup.find_all("form")
    if forms:
        form_lines = []
        for i, form in enumerate(forms[:5], 1):
            action = form.get("action", "(no action)")
            method = form.get("method", "GET").upper()
            form_lines.append(f"  Form {i}: action={action} method={method}")

            for inp in form.find_all(["input", "textarea", "select"]):
                itype = inp.get("type", "text")
                iname = inp.get("name", inp.get("id", ""))
                iplaceholder = inp.get("placeholder", "")
                label = f"type={itype}"
                if iname:
                    label += f" name={iname}"
                if iplaceholder:
                    label += f' placeholder="{iplaceholder[:50]}"'
                form_lines.append(f"    - INPUT: {label}")

            for btn in form.find_all(["button", "input"], attrs={"type": re.compile(r"submit|button", re.I)}):
                btn_text = btn.get_text(strip=True) or btn.get("value", "")
                if btn_text:
                    form_lines.append(f"    - BUTTON: {btn_text[:60]}")

        sections.append("FORMS:\n" + "\n".join(form_lines))
    else:
        sections.append("FORMS: none detected")

    # ---- 5. Navigation links ----
    nav_links: list[str] = []
    for nav in soup.find_all(["nav", "header"]):
        for a in nav.find_all("a", href=True):
            text = a.get_text(strip=True)
            href = str(a["href"])
            if text:
                nav_links.append(f"{text} ({href})")
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_nav = []
    for link in nav_links:
        if link not in seen:
            unique_nav.append(link)
            seen.add(link)
    if unique_nav:
        sections.append("NAV_LINKS: " + " | ".join(unique_nav[:20]))

    # ---- 6. Auth-related text snippets ----
    body_text = soup.get_text(separator=" ").lower()
    body_text = re.sub(r"\s+", " ", body_text)
    found_keywords = [kw for kw in _AUTH_KEYWORDS if kw in body_text]
    if found_keywords:
        sections.append("AUTH_KEYWORDS_FOUND: " + ", ".join(found_keywords[:15]))

    # ---- 7. SPA / framework detection ----
    raw_lower = raw_html.lower()
    spa_hits = [label for marker, label in _SPA_MARKERS.items() if marker.lower() in raw_lower]
    if spa_hits:
        sections.append("SPA_INDICATORS: " + ", ".join(spa_hits))

    # ---- 8. HTML size / complexity signal ----
    visible_text_len = len(body_text.strip())
    if visible_text_len < 200:
        sections.append(f"HTML_VISIBLE_TEXT_LENGTH: {visible_text_len} chars (very short — possible SPA shell)")
    else:
        sections.append(f"HTML_VISIBLE_TEXT_LENGTH: {visible_text_len} chars")

    summary = "\n\n".join(sections)
    if len(summary) > max_chars:
        summary = summary[: max_chars - 3] + "..."

    return summary
