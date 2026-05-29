"""
tests/test_prompts.py — Unit tests for Tier 2 LLM prompt generation and parsing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from tier2.prompts import build_analysis_prompt, parse_llm_response


class TestPromptBuilder:
    def test_builds_openai_message_list(self):
        rule_out = {"rule_verdict": "PARTIAL", "rule_score": 50, "service_type_guess": "MIXED"}
        probe_sum = {"paths": {"/": {"status_code": 200}}}
        
        messages = build_analysis_prompt("example.com", rule_out, probe_sum, "TITLE: hello")
        
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert "security analyst" in messages[0]["content"]
        
        assert messages[1]["role"] == "user"
        assert "DOMAIN: example.com" in messages[1]["content"]
        assert "TITLE: hello" in messages[1]["content"]


class TestResponseParser:
    def test_parses_clean_json(self):
        raw = '{"verdict": "PROTECTED", "confidence": 95, "service_type": "WEB_APP", "needs_browser_escalation": false}'
        parsed = parse_llm_response(raw)
        assert parsed["verdict"] == "PROTECTED"
        assert parsed["confidence"] == 95
        assert parsed["service_type"] == "WEB_APP"
        assert parsed["needs_browser_escalation"] is False

    def test_strips_markdown_fences(self):
        raw = 'Here is the analysis:\n```json\n{"verdict": "OPEN", "confidence": 80}\n```\nHope this helps.'
        parsed = parse_llm_response(raw)
        assert parsed["verdict"] == "OPEN"
        assert parsed["confidence"] == 80

    def test_strips_qwen3_thinking_blocks(self):
        raw = '<think>\nThinking about this...\n</think>\n{"verdict": "PARTIAL", "confidence": 50}'
        parsed = parse_llm_response(raw)
        assert parsed["verdict"] == "PARTIAL"
        assert parsed["confidence"] == 50

    def test_forces_escalation_on_low_confidence(self):
        # LLM returns false, but confidence is < 40 -> parser must override
        raw = '{"verdict": "UNKNOWN", "confidence": 20, "needs_browser_escalation": false}'
        parsed = parse_llm_response(raw)
        assert parsed["needs_browser_escalation"] is True

    def test_handles_invalid_json_gracefully(self):
        raw = 'This is just text, not JSON at all.'
        parsed = parse_llm_response(raw)
        assert parsed["verdict"] == "UNKNOWN"
        assert parsed["needs_browser_escalation"] is True
        assert "parsing failed" in parsed["browser_escalation_reason"]

    def test_normalizes_unknown_enums(self):
        raw = '{"verdict": "WEIRD_VERDICT", "service_type": "DATABASE"}'
        parsed = parse_llm_response(raw)
        assert parsed["verdict"] == "UNKNOWN"
        assert parsed["service_type"] == "UNKNOWN"
