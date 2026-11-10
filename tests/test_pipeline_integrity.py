"""
Regression tests for pipeline-integrity defects.

Each test here covers a failure that was silent: the pipeline returned a
plausible-looking answer that was wrong, rather than raising.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.context.graph import ContextGraphBuilder
from sentinel.context.python_extractor import PythonRouteExtractor
from sentinel.normalizer import FindingNormalizer
from sentinel.ranker import RuleBasedRanker
from sentinel.schemas import ContextAnnotation, RawFinding, SecurityFinding


def _finding(**kw) -> SecurityFinding:
    base = dict(
        canonical_id="abc123",
        scanner="bandit",
        rule_id="B608",
        file_path="app/views.py",
        line_start=12,
        line_end=12,
        severity="high",
        confidence="high",
        cwe_id="CWE-89",
        message="possible SQL injection",
    )
    base.update(kw)
    return SecurityFinding(**base)


class TestFingerprintSurvivesLineShift:
    """canonical_id pins a finding to a line, so a patch that inserts a line
    above it changed the id and made the rescan report the untouched
    vulnerability as fixed."""

    def test_canonical_id_changes_when_line_shifts(self):
        a = SecurityFinding.make_canonical_id("app.py", 12, "CWE-89")
        b = SecurityFinding.make_canonical_id("app.py", 13, "CWE-89")
        assert a != b

    def test_fingerprint_is_stable_across_line_shift(self):
        before = _finding(line_start=12, line_end=12)
        after = _finding(line_start=18, line_end=18, canonical_id="different")
        assert before.fingerprint == after.fingerprint

    def test_fingerprint_differs_for_different_rule(self):
        sqli = _finding(cwe_id="CWE-89")
        secret = _finding(cwe_id="CWE-798")
        assert sqli.fingerprint != secret.fingerprint

    def test_fingerprint_differs_across_files(self):
        here = _finding(file_path="a.py")
        there = _finding(file_path="b.py")
        assert here.fingerprint != there.fingerprint


class TestRepoPathConfinement:
    def test_path_outside_allowed_roots_is_rejected(self, tmp_path, monkeypatch):
        from sentinel import server

        allowed = tmp_path / "allowed"
        outside = tmp_path / "outside"
        allowed.mkdir()
        outside.mkdir()
        monkeypatch.setenv("SENTINEL_ALLOWED_ROOTS", str(allowed))

        assert server._validate_repo_path(str(allowed)) == allowed.resolve()
        with pytest.raises(ValueError, match="outside the allowed roots"):
            server._validate_repo_path(str(outside))

    def test_traversal_cannot_escape_allowed_root(self, tmp_path, monkeypatch):
        from sentinel import server

        allowed = tmp_path / "allowed"
        secret = tmp_path / "secret"
        allowed.mkdir()
        secret.mkdir()
        monkeypatch.setenv("SENTINEL_ALLOWED_ROOTS", str(allowed))

        escape = allowed / ".." / "secret"
        with pytest.raises(ValueError, match="outside the allowed roots"):
            server._validate_repo_path(str(escape))


class TestVerificationPathsArePortable:
    def test_no_hardcoded_windows_separator(self):
        source = Path("src/sentinel/verification.py").read_text(encoding="utf-8")
        assert 'replace("/", "\\\\")' not in source

    def test_missing_file_is_inconclusive_not_clear(self, tmp_path):
        from sentinel.verification import RescanEngine, RescanOutcome

        engine = RescanEngine(tmp_path)
        outcome, _msg = engine._rescan_with_bandit(_finding(file_path="gone.py"))
        assert outcome is RescanOutcome.INCONCLUSIVE

    def test_unsupported_scanner_is_inconclusive(self, tmp_path):
        from sentinel.verification import RescanEngine, RescanOutcome

        engine = RescanEngine(tmp_path)
        outcome, _msg = engine.rescan(_finding(scanner="trivy"))
        assert outcome is RescanOutcome.INCONCLUSIVE


class TestImportResolution:
    def test_dotted_specifier_is_not_truncated(self, tmp_path):
        (tmp_path / "config.prod.js").write_text("module.exports = {}", encoding="utf-8")
        (tmp_path / "config.js").write_text("module.exports = {}", encoding="utf-8")

        builder = ContextGraphBuilder(tmp_path)
        resolved = builder._resolve_import(tmp_path, "./config.prod")
        assert resolved is not None
        assert resolved.name == "config.prod.js"


class TestPythonRouteExtraction:
    """Bandit reports Python findings, so Python files must yield routes —
    otherwise SAST findings can never receive route context."""

    def test_flask_route_with_methods(self):
        source = (
            "@app.route('/api/users/<id>', methods=['GET', 'POST'])\n"
            "def get_user(id):\n"
            "    pass\n"
        )
        routes = PythonRouteExtractor().extract_routes(source, "app.py")
        assert len(routes) == 1
        assert routes[0].route_path == "/api/users/<id>"
        assert sorted(routes[0].http_methods) == ["GET", "POST"]
        assert routes[0].handler_name == "get_user"

    def test_flask_route_defaults_to_get(self):
        routes = PythonRouteExtractor().extract_routes(
            "@app.route('/health')\ndef health():\n    pass\n", "app.py"
        )
        assert routes[0].http_methods == ["GET"]

    def test_fastapi_verb_decorator(self):
        routes = PythonRouteExtractor().extract_routes(
            "@router.post('/items')\nasync def create():\n    pass\n", "api.py"
        )
        assert routes[0].route_path == "/items"
        assert routes[0].http_methods == ["POST"]

    def test_stacked_decorators_become_middleware(self):
        source = (
            "@app.route('/admin')\n"
            "@login_required\n"
            "@requires_role('admin')\n"
            "def admin_panel():\n"
            "    pass\n"
        )
        routes = PythonRouteExtractor().extract_routes(source, "admin.py")
        assert set(routes[0].middleware_names) == {"login_required", "requires_role"}

    def test_blueprint_named_after_its_feature_is_detected(self):
        # The router is bound to `admin`, which no name heuristic matches —
        # it has to be recognised from the Blueprint() construction.
        source = (
            "admin = Blueprint('admin', __name__)\n"
            "@admin.route('/admin/exec', methods=['POST'])\n"
            "@login_required\n"
            "def run_expression():\n"
            "    pass\n"
        )
        routes = PythonRouteExtractor().extract_routes(source, "admin.py")
        assert len(routes) == 1
        assert routes[0].route_path == "/admin/exec"
        assert routes[0].middleware_names == ["login_required"]

    def test_handler_line_span_is_recorded(self):
        source = (
            "@app.route('/a')\n"
            "def handler_a():\n"
            "    x = 1\n"
            "    return x\n"
        )
        routes = PythonRouteExtractor().extract_routes(source, "a.py")
        start, end = routes[0].handler_lines
        assert start <= 3 <= end

    def test_fastapi_depends_in_signature_is_middleware(self):
        source = (
            "router = APIRouter()\n"
            "@router.get('/items')\n"
            "async def read_items(user = Depends(get_current_user)):\n"
            "    pass\n"
        )
        routes = PythonRouteExtractor().extract_routes(source, "api.py")
        assert routes[0].middleware_names == ["get_current_user"]

    def test_fastapi_depends_in_decorator_kwarg_is_middleware(self):
        source = (
            "router = APIRouter()\n"
            "@router.post('/admin', dependencies=[Depends(verify_admin)])\n"
            "async def admin_action():\n"
            "    pass\n"
        )
        routes = PythonRouteExtractor().extract_routes(source, "api.py")
        assert routes[0].middleware_names == ["verify_admin"]

    def test_fastapi_route_without_depends_has_no_middleware(self):
        source = (
            "router = APIRouter()\n"
            "@router.get('/public')\n"
            "async def public(limit: int = 10):\n"
            "    pass\n"
        )
        routes = PythonRouteExtractor().extract_routes(source, "api.py")
        assert routes[0].middleware_names == []

    def test_non_router_object_is_ignored(self):
        routes = PythonRouteExtractor().extract_routes(
            "@cache.get('/key')\ndef f():\n    pass\n", "x.py"
        )
        assert routes == []

    def test_syntax_error_yields_no_routes(self):
        assert PythonRouteExtractor().extract_routes("def (((", "bad.py") == []

    def test_finding_is_attributed_to_its_own_handler(self, tmp_path):
        # Two routes in one file: each finding must get the route whose body
        # encloses it, not whichever route happens to sort first.
        (tmp_path / "app.py").write_text(
            "@app.route('/download')\n"
            "def download():\n"
            "    return send_file(request.args['name'])\n"
            "\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    return db.execute('SELECT * FROM t WHERE x=' + request.args['q'])\n",
            encoding="utf-8",
        )
        graph = ContextGraphBuilder(tmp_path).build()

        in_search = graph.annotate_finding(_finding(file_path="app.py", line_start=7))
        assert in_search.route_path == "/search"
        assert in_search.attribution_confidence == "handler"

        in_download = graph.annotate_finding(_finding(file_path="app.py", line_start=3))
        assert in_download.route_path == "/download"

    def test_shared_helper_attributes_to_the_unprotected_route(self, tmp_path):
        # helpers.py is reachable from both an open and a guarded route;
        # the open one is the real exposure.
        (tmp_path / "helpers.py").write_text("def run(x):\n    return eval(x)\n",
                                             encoding="utf-8")
        (tmp_path / "api.py").write_text(
            "router = APIRouter()\n"
            "from helpers import run\n"
            "@router.get('/aaa/guarded', dependencies=[Depends(verify_admin)])\n"
            "async def guarded():\n"
            "    return run('1')\n"
            "@router.get('/zzz/open')\n"
            "async def open_route():\n"
            "    return run('1')\n",
            encoding="utf-8",
        )
        graph = ContextGraphBuilder(tmp_path).build()
        annotation = graph.annotate_finding(_finding(file_path="helpers.py", line_start=2))
        # /aaa/guarded sorts first alphabetically, so only the guard count
        # can push the unprotected route ahead of it.
        assert annotation.route_path == "/zzz/open"
        assert annotation.middleware_names == []

    def test_module_level_finding_is_file_level_not_handler(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "SECRET = 'hardcoded'\n"
            "@app.route('/x')\n"
            "def x():\n"
            "    pass\n",
            encoding="utf-8",
        )
        graph = ContextGraphBuilder(tmp_path).build()
        annotation = graph.annotate_finding(_finding(file_path="app.py", line_start=1))
        assert annotation.attribution_confidence == "file"

    def test_bandit_finding_gets_route_context(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "@app.route('/search')\n"
            "@login_required\n"
            "def search(q):\n"
            "    return db.execute('SELECT * FROM t WHERE x=' + q)\n",
            encoding="utf-8",
        )
        graph = ContextGraphBuilder(tmp_path).build()
        annotation = graph.annotate_finding(_finding(file_path="app.py", line_start=4))
        assert annotation.route_path == "/search"
        assert "login_required" in annotation.middleware_names


class TestExpressUseIsNotARoute:
    def test_static_mount_is_not_treated_as_a_route(self, tmp_path):
        (tmp_path / "server.js").write_text(
            "app.use('/assets/public/images', express.static('public'));\n",
            encoding="utf-8",
        )
        graph = ContextGraphBuilder(tmp_path).build()
        annotation = graph.annotate_finding(_finding(file_path="server.js"))
        assert annotation.route_path is None


class TestCorroborationSurvivesDeduplication:
    def test_second_scanner_is_recorded(self, tmp_path):
        raw = [
            RawFinding(
                scanner="bandit", rule_id="B608", file_path=str(tmp_path / "a.py"),
                line_start=3, line_end=3, severity="high", confidence="medium",
                message="sqli", cwe_id="CWE-89",
            ),
            RawFinding(
                scanner="semgrep", rule_id="sqli", file_path=str(tmp_path / "a.py"),
                line_start=3, line_end=3, severity="high", confidence="high",
                message="sqli", cwe_id="CWE-89",
            ),
        ]
        (tmp_path / "a.py").write_text("x = 1\ny = 2\nz = 3\n", encoding="utf-8")
        findings = FindingNormalizer(tmp_path).normalize(raw)

        assert len(findings) == 1
        assert findings[0].scanner == "semgrep"  # higher confidence wins
        assert "bandit" in findings[0].corroborated_by


class TestDistinctRulesAtOneLineSurvive:
    """canonical_id is file+line+CWE, so two different rules from one scanner
    hash identically and one was being discarded."""

    def test_two_rules_same_line_same_cwe_both_kept(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n" * 5, encoding="utf-8")
        raw = [
            RawFinding(
                scanner="bandit", rule_id="B602", file_path=str(tmp_path / "a.py"),
                line_start=3, line_end=3, severity="low", confidence="high",
                message="subprocess with shell=True", cwe_id="CWE-78",
            ),
            RawFinding(
                scanner="bandit", rule_id="B607", file_path=str(tmp_path / "a.py"),
                line_start=3, line_end=3, severity="low", confidence="high",
                message="partial executable path", cwe_id="CWE-78",
            ),
        ]
        findings = FindingNormalizer(tmp_path).normalize(raw)
        assert {f.rule_id for f in findings} == {"B602", "B607"}

    def test_exact_duplicate_from_one_scanner_is_still_merged(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n" * 5, encoding="utf-8")
        raw = [
            RawFinding(
                scanner="bandit", rule_id="B602", file_path=str(tmp_path / "a.py"),
                line_start=3, line_end=3, severity="low", confidence="low",
                message="dup", cwe_id="CWE-78",
            ),
            RawFinding(
                scanner="bandit", rule_id="B602", file_path=str(tmp_path / "a.py"),
                line_start=3, line_end=3, severity="low", confidence="high",
                message="dup", cwe_id="CWE-78",
            ),
        ]
        findings = FindingNormalizer(tmp_path).normalize(raw)
        assert len(findings) == 1
        assert findings[0].confidence == "high"


class TestRankerScalesAreComparable:
    def test_maxed_finding_scores_one_regardless_of_scanner(self):
        ranker = RuleBasedRanker()
        context = ContextAnnotation(route_path="/admin", middleware_names=[])

        sast = ranker.rank(
            _finding(scanner="bandit", severity="critical",
                     confidence="high", cwe_id="CWE-89", corroborated_by=["trivy"]),
            context,
        )
        dependency = ranker.rank(
            _finding(scanner="trivy", severity="critical",
                     confidence="high", cwe_id="CWE-89", corroborated_by=["bandit"]),
            None,
        )
        assert sast.score == pytest.approx(1.0)
        assert dependency.score == pytest.approx(1.0)

    @pytest.mark.parametrize(
        "decorator",
        ["login_required", "jwt_required", "requires_role", "roles_required",
         "admin_required", "permission_required"],
    )
    def test_python_auth_decorators_are_recognised(self, decorator):
        # snake_case reads in the opposite order to the camelCase hints, so
        # 'requirelogin' does not match 'login_required'.
        ranker = RuleBasedRanker()
        assessment = ranker.rank(
            _finding(),
            ContextAnnotation(route_path="/admin", middleware_names=[decorator]),
        )
        assert assessment.feature_breakdown["auth_present_penalty"] > 0, decorator
        assert assessment.feature_breakdown["exposure_bonus"] == 0

    def test_express_session_does_not_count_as_auth(self):
        ranker = RuleBasedRanker()
        assessment = ranker.rank(
            _finding(),
            ContextAnnotation(route_path="/x", middleware_names=["session"]),
        )
        assert assessment.feature_breakdown["exposure_bonus"] > 0
        assert assessment.feature_breakdown["auth_present_penalty"] == 0
