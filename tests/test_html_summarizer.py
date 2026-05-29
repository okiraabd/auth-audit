"""
tests/test_html_summarizer.py — Unit tests for Tier 2 HTML summarization.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from tier2.html_summarizer import summarize_html


class TestHtmlSummarizer:
    def test_empty_html_returns_empty_string(self):
        assert summarize_html("") == ""
        assert summarize_html("   \n  ") == ""

    def test_extracts_title_and_meta(self):
        html = """
        <html>
        <head>
            <title>My App Login</title>
            <meta name="description" content="Secure portal access">
        </head>
        <body></body>
        </html>
        """
        summary = summarize_html(html)
        assert "TITLE: My App Login" in summary
        assert "META_DESCRIPTION: Secure portal access" in summary

    def test_extracts_headings(self):
        html = "<h1>Welcome</h1><h2>Sign in below</h2><h3>Help</h3>"
        summary = summarize_html(html)
        assert "[H1] Welcome" in summary
        assert "[H2] Sign in below" in summary
        assert "[H3] Help" in summary

    def test_extracts_forms_and_inputs(self):
        html = """
        <form action="/api/login" method="POST">
            <input type="text" name="username" placeholder="Email" />
            <input type="password" name="pwd" />
            <button type="submit">Log In</button>
        </form>
        """
        summary = summarize_html(html)
        assert "action=/api/login method=POST" in summary
        assert "type=text name=username" in summary
        assert "type=password name=pwd" in summary
        assert "BUTTON: Log In" in summary

    def test_extracts_auth_keywords(self):
        html = "<body><p>Please remember to sign in and use two-factor auth.</p></body>"
        summary = summarize_html(html)
        assert "AUTH_KEYWORDS_FOUND:" in summary
        assert "sign in" in summary
        assert "two-factor" in summary

    def test_spa_detection(self):
        html = '<body><div id="root"></div><script>window.__INITIAL_STATE__={}</script></body>'
        summary = summarize_html(html)
        assert "SPA_INDICATORS:" in summary
        assert "React/generic SPA shell" in summary
        assert "Redux/Vuex state injection" in summary

    def test_truncation_preserves_priority_sections(self):
        long_html = "<html><title>Important</title><body>" + ("<p>padding</p>" * 500) + "</body></html>"
        summary = summarize_html(long_html, max_chars=40)
        # Title is at the top, should survive truncation
        assert "TITLE: Important" in summary
        assert len(summary) <= 40
        # When truncation happens, we append ... so the string MUST end with ...
        assert summary.endswith("...")
