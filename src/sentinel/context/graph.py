"""
ContextGraphBuilder — builds a NetworkX graph of Express.js application structure.

Graph nodes:
  - Route:   route_path, http_methods
  - Handler: file_path, function_name
  - Middleware: name
  - File:    posix_path (all JS/TS files in repo)

Graph edges:
  - Route -[HAS_HANDLER]→ Handler
  - Route -[HAS_MIDDLEWARE]→ Middleware  (ordered, attrs: position=int)
  - File  -[IMPORTS]→ File               (via require/import static analysis)

The graph answers two questions for each SecurityFinding:
  1. Is the finding's file attributable to any Express.js route?
     (via File → Handler ← Route path, or File ← File IMPORTS chain)
  2. What middleware names are on that route?

Both claims are structural only — no taint analysis, no enforcement verification.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import networkx as nx

from sentinel.context.extractor import RouteInfo, get_extractor
from sentinel.context.python_extractor import PythonRouteExtractor
from sentinel.schemas import ContextAnnotation, SecurityFinding


# Static require/import patterns for file dependency traversal
_REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_RE = re.compile(r"""import\s+.*?\s+from\s+['"]([^'"]+)['"]""")
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}
_PY_EXTENSIONS = {".py"}

# Directories that never contain application routes
_SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "site-packages"}

# How far to follow IMPORTS edges when attributing a file to a route.
# Unbounded traversal attributes every transitively imported file to the
# route, and since an app entrypoint imports nearly everything, that makes
# almost all files inherit some route's middleware.
_MAX_IMPORT_DEPTH = 2


class ContextGraph:
    """Holds the in-memory application context graph for one repository."""

    def __init__(self) -> None:
        self._g: nx.DiGraph = nx.DiGraph()
        # file_posix_path → set of route_paths that can reach it
        self._file_to_routes: dict[str, list[RouteInfo]] = {}

    def annotate_finding(self, finding: SecurityFinding) -> ContextAnnotation:
        """
        Return a ContextAnnotation for a finding's file path.

        Returns unknown attribution if the file is not reachable from any route.
        """
        routes = self._file_to_routes.get(finding.file_path, [])

        if not routes:
            return ContextAnnotation(
                route_path=None,
                http_methods=[],
                middleware_names=[],
                attribution_confidence="unknown",
            )

        # Prefer the route whose handler body encloses the finding. Without
        # this every finding in a file inherits whichever route happens to
        # sort first, so a SQL injection in search() is reported against an
        # unrelated route in the same module.
        enclosing = next(
            (
                r for r in routes
                if r.handler_file == finding.file_path
                and r.handler_lines is not None
                and r.handler_lines[0] <= finding.line_start <= r.handler_lines[1]
            ),
            None,
        )

        best = enclosing or routes[0]
        return ContextAnnotation(
            route_path=best.route_path,
            http_methods=best.http_methods,
            middleware_names=best.middleware_names,
            # 'handler' is claimed only when the finding is literally inside
            # that handler's body; everything else is file-level reachability.
            attribution_confidence="handler" if enclosing is not None else "file",
        )

    @property
    def graph(self) -> nx.DiGraph:
        return self._g


class ContextGraphBuilder:
    """Builds a ContextGraph from a repository directory."""

    def __init__(self, repo_root: Path) -> None:
        self._repo_root = repo_root.resolve()
        self._extractor = get_extractor()
        self._py_extractor = PythonRouteExtractor()

    def build(self) -> ContextGraph:
        ctx = ContextGraph()

        # 1. Find source files. Python is scanned alongside JS because Bandit
        #    reports Python findings — without this the SAST half of the
        #    pipeline can never receive route context.
        js_files: list[Path] = []
        py_files: list[Path] = []
        for f in self._repo_root.rglob("*"):
            if _SKIP_DIRS.intersection(f.parts):
                continue
            if f.suffix in _JS_EXTENSIONS:
                js_files.append(f)
            elif f.suffix in _PY_EXTENSIONS:
                py_files.append(f)

        # 2. Extract routes from each file
        all_routes: list[RouteInfo] = []
        for source_file, extractor in (
            *((f, self._extractor) for f in js_files),
            *((f, self._py_extractor) for f in py_files),
        ):
            try:
                source = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            posix_path = self._to_posix(source_file)
            all_routes.extend(extractor.extract_routes(source, posix_path))

            # Add File node
            ctx.graph.add_node(f"file:{posix_path}", kind="File", path=posix_path)

        # 3. Build import graph (static require/import)
        self._add_import_edges(ctx, js_files)
        self._add_python_import_edges(ctx, py_files)

        # 4. Add Route/Handler/Middleware nodes and edges
        for route in all_routes:
            route_id = f"route:{route.route_path}:{','.join(route.http_methods)}"
            handler_id = f"handler:{route.handler_file}:{route.handler_name}"

            ctx.graph.add_node(
                route_id,
                kind="Route",
                route_path=route.route_path,
                http_methods=route.http_methods,
            )
            ctx.graph.add_node(
                handler_id,
                kind="Handler",
                file_path=route.handler_file,
                function_name=route.handler_name,
            )
            ctx.graph.add_edge(route_id, handler_id, rel="HAS_HANDLER")

            for pos, mw_name in enumerate(route.middleware_names):
                mw_id = f"middleware:{mw_name}"
                ctx.graph.add_node(mw_id, kind="Middleware", name=mw_name)
                ctx.graph.add_edge(route_id, mw_id, rel="HAS_MIDDLEWARE", position=pos)

        # 5. Build file→routes lookup (direct handler match + import reachability)
        self._build_file_to_routes(ctx, all_routes)

        return ctx

    def _add_import_edges(self, ctx: ContextGraph, js_files: list[Path]) -> None:
        for js_file in js_files:
            try:
                source = js_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            src_posix = self._to_posix(js_file)
            imports = _REQUIRE_RE.findall(source) + _IMPORT_RE.findall(source)

            for imp in imports:
                if not imp.startswith("."):
                    continue  # skip node_modules
                resolved = self._resolve_import(js_file.parent, imp)
                if resolved:
                    dst_posix = self._to_posix(resolved)
                    ctx.graph.add_node(f"file:{dst_posix}", kind="File", path=dst_posix)
                    ctx.graph.add_edge(
                        f"file:{src_posix}",
                        f"file:{dst_posix}",
                        rel="IMPORTS",
                    )

    def _add_python_import_edges(self, ctx: ContextGraph, py_files: list[Path]) -> None:
        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                continue

            src_posix = self._to_posix(py_file)
            for node in ast.walk(tree):
                resolved: list[Path | None] = []
                if isinstance(node, ast.Import):
                    resolved = [
                        self._resolve_py_module(a.name, py_file, 0)
                        for a in node.names
                    ]
                elif isinstance(node, ast.ImportFrom):
                    base = node.module or ""
                    resolved = [self._resolve_py_module(base, py_file, node.level)]
                    # `from pkg import module` — the imported name may itself
                    # be a module rather than an attribute of pkg.
                    for alias in node.names:
                        dotted = f"{base}.{alias.name}" if base else alias.name
                        resolved.append(
                            self._resolve_py_module(dotted, py_file, node.level)
                        )
                else:
                    continue

                for target in resolved:
                    if target is None:
                        continue
                    dst_posix = self._to_posix(target)
                    if dst_posix == src_posix:
                        continue
                    ctx.graph.add_node(
                        f"file:{dst_posix}", kind="File", path=dst_posix
                    )
                    ctx.graph.add_edge(
                        f"file:{src_posix}", f"file:{dst_posix}", rel="IMPORTS"
                    )

    def _resolve_py_module(
        self, dotted: str, from_file: Path, level: int
    ) -> Path | None:
        """Resolve a Python module reference to a file inside the repository.

        Only intra-repo modules resolve; third-party and stdlib imports return
        None, which keeps the graph to first-party application code.
        """
        if level > 0:
            base_dir = from_file.parent
            for _ in range(level - 1):
                base_dir = base_dir.parent
        else:
            base_dir = self._repo_root

        parts = [p for p in dotted.split(".") if p] if dotted else []
        candidate = base_dir.joinpath(*parts) if parts else base_dir

        for option in (
            candidate.parent / (candidate.name + ".py") if parts else None,
            candidate / "__init__.py",
        ):
            if option is None or not option.is_file():
                continue
            resolved = option.resolve()
            try:
                resolved.relative_to(self._repo_root)
            except ValueError:
                return None
            return resolved
        return None

    def _resolve_import(self, base_dir: Path, specifier: str) -> Path | None:
        """
        Resolve a relative require/import specifier to an absolute path.
        Tries .js, .mjs, .ts extensions and index files.
        """
        candidate = (base_dir / specifier).resolve()
        for ext in ("", ".js", ".mjs", ".cjs", ".ts"):
            # Append rather than with_suffix: './config.prod' must resolve to
            # config.prod.js, not config.js.
            p = candidate.parent / (candidate.name + ext) if ext else candidate
            if p.is_file():
                return p
        # Try as directory with index file
        for idx_name in ("index.js", "index.mjs", "index.ts"):
            idx = candidate / idx_name
            if idx.is_file():
                return idx
        return None

    def _build_file_to_routes(
        self, ctx: ContextGraph, all_routes: list[RouteInfo]
    ) -> None:
        """
        Map each file to the routes that can reach it.
        Direct handler match takes priority over transitive import reachability.
        """
        # (depth, route_path) is carried alongside each route so the final
        # ordering is deterministic rather than dependent on set iteration.
        scratch: dict[str, list[tuple[int, str, RouteInfo]]] = {}

        # Depth 0 — the route's own handler file
        for route in all_routes:
            scratch.setdefault(route.handler_file, []).append(
                (0, route.route_path, route)
            )

        # Transitive — files the handler imports, bounded depth
        for route in all_routes:
            handler_node = f"file:{route.handler_file}"
            if handler_node not in ctx.graph:
                continue
            try:
                depths = nx.single_source_shortest_path_length(
                    ctx.graph, handler_node, cutoff=_MAX_IMPORT_DEPTH
                )
            except nx.NetworkXError:
                continue
            for node_id, depth in depths.items():
                if depth == 0 or not node_id.startswith("file:"):
                    continue
                file_posix = node_id[len("file:"):]
                scratch.setdefault(file_posix, []).append(
                    (depth, route.route_path, route)
                )

        for file_posix, entries in scratch.items():
            # Among routes at the same distance, the one with the fewest
            # guards wins. A helper imported by both a protected and an
            # unprotected route is exposed through the unprotected one, and
            # reporting the protected route instead understates the risk —
            # the ranker treats middleware presence as mitigating.
            entries.sort(
                key=lambda e: (e[0], len(e[2].middleware_names), e[1], e[2].handler_file)
            )
            ordered: list[RouteInfo] = []
            seen: set[tuple] = set()
            for _depth, _path, route in entries:
                key = (route.route_path, tuple(route.http_methods), route.handler_file)
                if key in seen:
                    continue
                seen.add(key)
                ordered.append(route)
            ctx._file_to_routes[file_posix] = ordered

    def _to_posix(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._repo_root)).replace("\\", "/")
        except ValueError:
            return path.as_posix()
