"""
Week 8-10 milestone gate: ContextGraphBuilder extracts Express.js routes and
middleware from the JS fixture, and annotate_finding returns the correct
ContextAnnotation for findings in those files.

Two structural claims verified:
  1. A finding's file is attributable to an Express.js route
  2. Middleware names declared on that route are captured

Scope: structural analysis only. No enforcement or taint claims.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.context.extractor import _TREESITTER_AVAILABLE, RegexExtractor

FIXTURE_DIR = Path(__file__).parent / "fixtures"
EXPRESS_FIXTURE = FIXTURE_DIR / "vulnerable_express_app.js"

# Both extractors must produce results; tree-sitter gives richer data
treesitter_missing = not _TREESITTER_AVAILABLE


class TestRegexExtractor:
    """Regex fallback extractor works even without tree-sitter."""

    def test_extracts_routes(self):
        ext = RegexExtractor()
        source = EXPRESS_FIXTURE.read_text(encoding="utf-8")
        routes = ext.extract_routes(source, str(EXPRESS_FIXTURE))

        route_paths = {r.route_path for r in routes}
        assert "/api/products" in route_paths
        assert "/api/users/:id" in route_paths
        assert "/api/admin/settings" in route_paths

    def test_extracts_http_methods(self):
        ext = RegexExtractor()
        source = EXPRESS_FIXTURE.read_text(encoding="utf-8")
        routes = ext.extract_routes(source, str(EXPRESS_FIXTURE))

        by_path = {r.route_path: r for r in routes}
        assert "GET" in by_path["/api/products"].http_methods
        assert "POST" in by_path["/api/admin/settings"].http_methods

    def test_extracts_middleware_names(self):
        ext = RegexExtractor()
        source = EXPRESS_FIXTURE.read_text(encoding="utf-8")
        routes = ext.extract_routes(source, str(EXPRESS_FIXTURE))

        by_path = {r.route_path: r for r in routes}
        assert "authMiddleware" in by_path["/api/users/:id"].middleware_names
        assert "authMiddleware" in by_path["/api/admin/settings"].middleware_names


@pytest.mark.skipif(treesitter_missing, reason="tree-sitter not installed")
class TestTreeSitterExtractor:
    """tree-sitter primary extractor produces identical structural claims."""

    def test_extracts_three_routes(self):
        from sentinel.context.extractor import TreeSitterExtractor

        ext = TreeSitterExtractor()
        source = EXPRESS_FIXTURE.read_text(encoding="utf-8")
        routes = ext.extract_routes(source, str(EXPRESS_FIXTURE))

        assert len(routes) == 3, f"Expected 3 routes, got {len(routes)}: {[r.route_path for r in routes]}"

    def test_extracts_route_paths(self):
        from sentinel.context.extractor import TreeSitterExtractor

        ext = TreeSitterExtractor()
        source = EXPRESS_FIXTURE.read_text(encoding="utf-8")
        routes = ext.extract_routes(source, str(EXPRESS_FIXTURE))

        paths = {r.route_path for r in routes}
        assert "/api/products" in paths
        assert "/api/users/:id" in paths
        assert "/api/admin/settings" in paths

    def test_public_route_has_no_middleware(self):
        from sentinel.context.extractor import TreeSitterExtractor

        ext = TreeSitterExtractor()
        source = EXPRESS_FIXTURE.read_text(encoding="utf-8")
        routes = ext.extract_routes(source, str(EXPRESS_FIXTURE))

        products = next(r for r in routes if r.route_path == "/api/products")
        assert products.middleware_names == [], (
            "Public /api/products route should have no middleware"
        )

    def test_protected_route_has_auth_middleware(self):
        from sentinel.context.extractor import TreeSitterExtractor

        ext = TreeSitterExtractor()
        source = EXPRESS_FIXTURE.read_text(encoding="utf-8")
        routes = ext.extract_routes(source, str(EXPRESS_FIXTURE))

        users = next(r for r in routes if r.route_path == "/api/users/:id")
        assert "authMiddleware" in users.middleware_names, (
            "Protected /api/users/:id should list authMiddleware"
        )


class TestContextGraphBuilder:
    def test_build_returns_context_graph(self):
        from sentinel.context.graph import ContextGraphBuilder

        builder = ContextGraphBuilder(FIXTURE_DIR)
        graph = builder.build()
        assert graph is not None
        assert graph.graph.number_of_nodes() > 0

    def test_finding_in_js_file_gets_route_annotation(self):
        """A finding whose file_path matches the JS fixture gets a route annotation."""
        from sentinel.context.graph import ContextGraphBuilder
        from sentinel.schemas import SecurityFinding

        builder = ContextGraphBuilder(FIXTURE_DIR)
        graph = builder.build()

        # Create a mock finding in the JS fixture file
        finding = SecurityFinding(
            canonical_id=SecurityFinding.make_canonical_id("vulnerable_express_app.js", 36, "CWE-89"),
            scanner="bandit",
            rule_id="B608",
            file_path="vulnerable_express_app.js",
            line_start=36,
            line_end=36,
            severity="high",
            confidence="high",
            cwe_id="CWE-89",
            message="SQL injection",
        )
        annotation = graph.annotate_finding(finding)

        assert annotation.route_path is not None, (
            "Finding in JS fixture should be attributed to a route"
        )
        assert annotation.route_path.startswith("/api/"), (
            f"Expected /api/... route, got: {annotation.route_path}"
        )

    def test_finding_in_unknown_file_gets_unknown_attribution(self):
        """A finding in a file not in the graph returns unknown attribution."""
        from sentinel.context.graph import ContextGraphBuilder
        from sentinel.schemas import SecurityFinding

        builder = ContextGraphBuilder(FIXTURE_DIR)
        graph = builder.build()

        finding = SecurityFinding(
            canonical_id=SecurityFinding.make_canonical_id("nonexistent.py", 1, "CWE-89"),
            scanner="bandit",
            rule_id="B608",
            file_path="nonexistent.py",
            line_start=1,
            line_end=1,
            severity="high",
            confidence="high",
            cwe_id="CWE-89",
            message="SQL injection",
        )
        annotation = graph.annotate_finding(finding)

        assert annotation.attribution_confidence == "unknown"
        assert annotation.route_path is None

    def test_annotation_disclaimer_always_present(self):
        """ContextAnnotation always carries its structural-only disclaimer."""
        from sentinel.context.graph import ContextGraphBuilder
        from sentinel.schemas import SecurityFinding

        builder = ContextGraphBuilder(FIXTURE_DIR)
        graph = builder.build()

        finding = SecurityFinding(
            canonical_id=SecurityFinding.make_canonical_id("nonexistent.py", 1, "CWE-89"),
            scanner="bandit",
            rule_id="B608",
            file_path="nonexistent.py",
            line_start=1,
            line_end=1,
            severity="high",
            confidence="high",
            cwe_id="CWE-89",
            message="test",
        )
        annotation = graph.annotate_finding(finding)
        assert annotation.disclaimer, "Disclaimer must always be set"
        assert "structural" in annotation.disclaimer.lower()
