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

import re
from pathlib import Path

import networkx as nx

from sentinel.context.extractor import RouteInfo, get_extractor
from sentinel.schemas import ContextAnnotation, SecurityFinding


# Static require/import patterns for file dependency traversal
_REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_RE = re.compile(r"""import\s+.*?\s+from\s+['"]([^'"]+)['"]""")
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}


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

        # Use the first matching route (most specific — direct handler match first)
        best = routes[0]
        return ContextAnnotation(
            route_path=best.route_path,
            http_methods=best.http_methods,
            middleware_names=best.middleware_names,
            attribution_confidence="handler" if best.handler_file == finding.file_path else "file",
        )

    @property
    def graph(self) -> nx.DiGraph:
        return self._g


class ContextGraphBuilder:
    """Builds a ContextGraph from a repository directory."""

    def __init__(self, repo_root: Path) -> None:
        self._repo_root = repo_root.resolve()
        self._extractor = get_extractor()

    def build(self) -> ContextGraph:
        ctx = ContextGraph()

        # 1. Find all JS/TS files
        js_files = [
            f for f in self._repo_root.rglob("*")
            if f.suffix in _JS_EXTENSIONS
            and "node_modules" not in f.parts
        ]

        # 2. Extract routes from each file
        all_routes: list[RouteInfo] = []
        for js_file in js_files:
            try:
                source = js_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            posix_path = self._to_posix(js_file)
            routes = self._extractor.extract_routes(source, posix_path)
            all_routes.extend(routes)

            # Add File node
            ctx.graph.add_node(f"file:{posix_path}", kind="File", path=posix_path)

        # 3. Build import graph (static require/import)
        self._add_import_edges(ctx, js_files)

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

    def _resolve_import(self, base_dir: Path, specifier: str) -> Path | None:
        """
        Resolve a relative require/import specifier to an absolute path.
        Tries .js, .mjs, .ts extensions and index files.
        """
        candidate = (base_dir / specifier).resolve()
        for ext in ("", ".js", ".mjs", ".cjs", ".ts"):
            p = candidate.with_suffix(ext) if ext else candidate
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
        # Direct: handler_file matches exactly
        for route in all_routes:
            ctx._file_to_routes.setdefault(route.handler_file, [])
            if route not in ctx._file_to_routes[route.handler_file]:
                ctx._file_to_routes[route.handler_file].insert(0, route)

        # Transitive: follow IMPORTS edges backward from handler files
        # (a file imported by a handler is attributed to that handler's routes)
        for route in all_routes:
            handler_node = f"file:{route.handler_file}"
            if handler_node not in ctx.graph:
                continue
            try:
                # Find all files reachable FROM this handler file via imports
                reachable = nx.descendants(ctx.graph, handler_node)
            except nx.NetworkXError:
                continue
            for node_id in reachable:
                if not node_id.startswith("file:"):
                    continue
                file_posix = node_id[len("file:"):]
                ctx._file_to_routes.setdefault(file_posix, [])
                # Only add if not already directly attributed
                if route not in ctx._file_to_routes[file_posix]:
                    ctx._file_to_routes[file_posix].append(route)

    def _to_posix(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._repo_root)).replace("\\", "/")
        except ValueError:
            return path.as_posix()
