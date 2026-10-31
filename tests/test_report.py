"""Tests for ReportGenerator."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.report import ReportGenerator, _render_html, _severity_counts, _scanner_counts


# ---------------------------------------------------------------------------
# Minimal fixture data
# ---------------------------------------------------------------------------

def _make_finding_dict(severity: str = "high", scanner: str = "bandit") -> dict:
    return {
        "finding": {
            "canonical_id": "abc123",
            "id": "uuid-1",
            "scanner": scanner,
            "rule_id": "B101",
            "file_path": "app.py",
            "line_start": 10,
            "line_end": 10,
            "severity": severity,
            "confidence": "high",
            "cwe_id": "CWE-89",
            "message": "SQL injection risk",
            "snippet": None,
            "is_dev_dependency": False,
            "requires_developer_action": True,
        },
        "context": {
            "route_path": "/api/search",
            "http_methods": ["GET"],
            "middleware_names": ["auth"],
            "attribution_confidence": "handler",
            "disclaimer": "Structural analysis only.",
        },
        "risk": {
            "finding_id": "uuid-1",
            "ranked_severity": "high",
            "ranker": "rule_based",
            "score": 0.85,
            "feature_breakdown": {},
        },
    }


def _make_report_data(findings: list[dict] | None = None) -> dict:
    if findings is None:
        findings = [
            _make_finding_dict("critical"),
            _make_finding_dict("high"),
            _make_finding_dict("medium", scanner="trivy"),
        ]
    return {
        "sentinel_version": "0.1.0",
        "generated_at": "2026-10-31T00:00:00+00:00",
        "finding_count": len(findings),
        "findings": findings,
        "audit_events": [],
    }


# ---------------------------------------------------------------------------
# Unit tests — _severity_counts, _scanner_counts
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_severity_counts_basic(self):
        data = _make_report_data()
        counts = _severity_counts(data["findings"])
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 0

    def test_scanner_counts(self):
        data = _make_report_data()
        counts = _scanner_counts(data["findings"])
        assert counts["bandit"] == 2
        assert counts["trivy"] == 1

    def test_empty_findings(self):
        counts = _severity_counts([])
        assert all(v == 0 for v in counts.values())


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

class TestRenderHtml:
    def test_html_contains_finding_count(self):
        data = _make_report_data()
        html = _render_html(data)
        assert "3" in html  # finding count
        assert "Sentinel Security Report" in html

    def test_html_severity_badge(self):
        data = _make_report_data()
        html = _render_html(data)
        assert "CRITICAL" in html
        assert "HIGH" in html
        assert "MEDIUM" in html

    def test_html_escapes_message(self):
        # Table cell must HTML-escape; JSON blob must escape </ to prevent script injection
        finding = _make_finding_dict()
        finding["finding"]["message"] = "<b>sql</b></script><img onerror=alert(1)>"
        data = _make_report_data([finding])
        html = _render_html(data)
        # Table cell is escaped via _esc()
        assert "&lt;b&gt;" in html
        # The ONLY </script> in the page must be the template's closing tag.
        # If </script> from the payload leaked raw, there would be 2+ occurrences.
        assert html.count("</script>") == 1

    def test_html_embeds_json_blob(self):
        data = _make_report_data()
        html = _render_html(data)
        assert "const _data" in html
        assert "downloadJson" in html

    def test_html_no_findings(self):
        data = _make_report_data([])
        html = _render_html(data)
        assert "No findings." in html

    def test_html_scanner_badge(self):
        data = _make_report_data()
        html = _render_html(data)
        assert "bandit" in html
        assert "trivy" in html


# ---------------------------------------------------------------------------
# ReportGenerator.write — integration (uses tmp_path)
# ---------------------------------------------------------------------------

class TestReportGeneratorWrite:
    def test_write_creates_json_and_html(self, tmp_path: Path):
        gen = ReportGenerator()
        data = _make_report_data()

        # Build minimal EnrichedFinding-like objects
        class FakeEF:
            def to_dict(self_inner):
                return data["findings"][0]

        json_path, html_path = gen.write([FakeEF()], [], tmp_path)
        assert json_path.exists()
        assert html_path.exists()
        assert json_path.suffix == ".json"
        assert html_path.suffix == ".html"

    def test_json_is_valid(self, tmp_path: Path):
        gen = ReportGenerator()

        class FakeEF:
            def to_dict(self_inner):
                return _make_finding_dict()

        json_path, _ = gen.write([FakeEF(), FakeEF()], [], tmp_path)
        loaded = json.loads(json_path.read_text(encoding="utf-8"))
        assert loaded["finding_count"] == 2
        assert len(loaded["findings"]) == 2

    def test_empty_scan_produces_valid_report(self, tmp_path: Path):
        gen = ReportGenerator()
        json_path, html_path = gen.write([], [], tmp_path)
        loaded = json.loads(json_path.read_text(encoding="utf-8"))
        assert loaded["finding_count"] == 0
        html = html_path.read_text(encoding="utf-8")
        assert "No findings." in html
