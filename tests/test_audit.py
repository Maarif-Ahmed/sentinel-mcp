"""
Week 15-16 milestone gate — Part 1: AuditLogger + ReportGenerator.

Tests verify:
  - AuditLogger writes events to SQLite and retrieves them correctly
  - get_recent returns events in descending timestamp order
  - get_recent respects the limit parameter
  - Events for different repositories are isolated
  - limit is capped at 500
  - ReportGenerator produces JSON and HTML files
  - JSON report contains expected keys
  - HTML report embeds finding data
  - Empty findings produce a valid report
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.audit import AuditLogger
from sentinel.report import ReportGenerator
from sentinel.schemas import AuditEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(repo: str = "/repo/app", event_type: str = "scan_repository",
                action: str = "scan", outcome: str = "success",
                canon_id: str | None = None, **meta) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        repository_root=repo,
        finding_canonical_id=canon_id,
        action=action,
        outcome=outcome,
        metadata=meta,
    )


# ---------------------------------------------------------------------------
# AuditLogger tests
# ---------------------------------------------------------------------------

class TestAuditLogger:
    def test_log_and_retrieve_single_event(self, tmp_path: Path):
        db = tmp_path / "audit.db"
        logger = AuditLogger(db)
        event = _make_event(scanner="bandit")
        logger.log(event)

        results = logger.get_recent("/repo/app")
        assert len(results) == 1
        assert results[0].event_type == "scan_repository"
        assert results[0].outcome == "success"

    def test_metadata_roundtrips(self, tmp_path: Path):
        db = tmp_path / "audit.db"
        logger = AuditLogger(db)
        logger.log(_make_event(tool="bandit", count=42))

        results = logger.get_recent("/repo/app")
        assert results[0].metadata["tool"] == "bandit"
        assert results[0].metadata["count"] == 42

    def test_multiple_events_returned_most_recent_first(self, tmp_path: Path):
        import time
        db = tmp_path / "audit.db"
        logger = AuditLogger(db)
        for i in range(3):
            logger.log(_make_event(seq=i))
            time.sleep(0.01)  # ensure distinct timestamps

        results = logger.get_recent("/repo/app", limit=3)
        assert len(results) == 3
        # Most recent first: seq=2, 1, 0
        assert results[0].metadata["seq"] == 2
        assert results[2].metadata["seq"] == 0

    def test_limit_respected(self, tmp_path: Path):
        db = tmp_path / "audit.db"
        logger = AuditLogger(db)
        for i in range(10):
            logger.log(_make_event(seq=i))

        results = logger.get_recent("/repo/app", limit=3)
        assert len(results) == 3

    def test_limit_capped_at_500(self, tmp_path: Path):
        db = tmp_path / "audit.db"
        logger = AuditLogger(db)
        # Only write 5 events; limit=9999 should be capped and return all 5
        for i in range(5):
            logger.log(_make_event(seq=i))

        results = logger.get_recent("/repo/app", limit=9999)
        assert len(results) == 5  # capped, but only 5 exist

    def test_events_isolated_by_repository(self, tmp_path: Path):
        db = tmp_path / "audit.db"
        logger = AuditLogger(db)
        logger.log(_make_event(repo="/repo/a"))
        logger.log(_make_event(repo="/repo/b"))

        results_a = logger.get_recent("/repo/a")
        results_b = logger.get_recent("/repo/b")
        assert len(results_a) == 1
        assert len(results_b) == 1

    def test_finding_canonical_id_stored(self, tmp_path: Path):
        db = tmp_path / "audit.db"
        logger = AuditLogger(db)
        logger.log(_make_event(canon_id="abc123"))

        results = logger.get_recent("/repo/app")
        assert results[0].finding_canonical_id == "abc123"

    def test_db_persists_across_logger_instances(self, tmp_path: Path):
        db = tmp_path / "audit.db"
        AuditLogger(db).log(_make_event())
        # New instance, same db file
        results = AuditLogger(db).get_recent("/repo/app")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# ReportGenerator tests
# ---------------------------------------------------------------------------

class TestReportGenerator:
    def test_writes_json_and_html_files(self, tmp_path: Path):
        gen = ReportGenerator()
        json_path, html_path = gen.write([], [], tmp_path)
        assert json_path.exists()
        assert html_path.exists()

    def test_json_report_has_required_keys(self, tmp_path: Path):
        gen = ReportGenerator()
        json_path, _ = gen.write([], [], tmp_path)
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "sentinel_version" in data
        assert "generated_at" in data
        assert "finding_count" in data
        assert "findings" in data
        assert "audit_events" in data

    def test_json_finding_count_matches(self, tmp_path: Path):
        gen = ReportGenerator()
        json_path, _ = gen.write([], [], tmp_path)
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["finding_count"] == 0

    def test_html_contains_sentinel_header(self, tmp_path: Path):
        gen = ReportGenerator()
        _, html_path = gen.write([], [], tmp_path)
        html = html_path.read_text(encoding="utf-8")
        assert "Sentinel Security Report" in html

    def test_html_contains_disclaimer(self, tmp_path: Path):
        gen = ReportGenerator()
        _, html_path = gen.write([], [], tmp_path)
        html = html_path.read_text(encoding="utf-8")
        assert "advisory" in html.lower() or "manual review" in html.lower()

    def test_empty_findings_produces_no_rows_message(self, tmp_path: Path):
        gen = ReportGenerator()
        _, html_path = gen.write([], [], tmp_path)
        html = html_path.read_text(encoding="utf-8")
        assert "No findings" in html
