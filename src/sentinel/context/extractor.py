"""
Express.js context extractor — tree-sitter based route and middleware analysis.

SCOPE (two structural claims only):
  1. Which Express.js route a finding's file is reachable from
     (via require/import traversal)
  2. Which middleware names are registered on that route before the handler

This does NOT claim:
  - Whether middleware enforces authentication
  - Whether user input flows to the finding
  - Whether the finding is exploitable

A regex fallback is used when tree-sitter is unavailable (MSVC build failure).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RouteInfo:
    """Structural information about a single Express.js route."""

    route_path: str          # e.g. "/api/users/:id"
    http_methods: list[str]  # e.g. ["GET"]
    handler_file: str        # POSIX path of the handler file
    handler_name: str        # function name or "<anonymous>"
    middleware_names: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tree-sitter extractor (primary)
# ---------------------------------------------------------------------------

# Lazy import — tree-sitter may not build on all Windows configurations.
# If import fails, _TREESITTER_AVAILABLE is False and we use the regex fallback.
_TREESITTER_AVAILABLE = False
_ts_language = None

try:
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser

    _JS_LANGUAGE = Language(tsjs.language())
    _ts_parser = Parser(_JS_LANGUAGE)
    _TREESITTER_AVAILABLE = True
except Exception:
    pass

# Express HTTP method names we recognise as route registrations
_EXPRESS_METHODS = {"get", "post", "put", "patch", "delete", "all", "use"}

# S-expression query for Express route calls:
# app.get("/path", [middleware...], handler)
# router.post("/path", handler)
_ROUTE_QUERY_PATTERN = """
(call_expression
  function: (member_expression
    object: (identifier) @router_obj
    property: (property_identifier) @method)
  arguments: (arguments
    . (string) @route_path
    (identifier)* @middleware
    (identifier) @handler))
"""


class TreeSitterExtractor:
    """Extracts Express.js routes from JS/TS source using tree-sitter CST queries."""

    def extract_routes(self, js_source: str, file_path: str) -> list[RouteInfo]:
        if not _TREESITTER_AVAILABLE:
            raise RuntimeError("tree-sitter is not available")

        try:
            from tree_sitter import Language, Query
            tree = _ts_parser.parse(js_source.encode())
            query = _JS_LANGUAGE.query(_ROUTE_QUERY_PATTERN)
            captures = query.captures(tree.root_node)
        except Exception:
            return []

        routes: list[RouteInfo] = []

        # Group captures by their parent call_expression node
        # captures: list of (node, capture_name) tuples
        grouped: dict[int, dict[str, list]] = {}
        for node, name in captures:
            parent_id = node.parent.id if node.parent else node.id
            if parent_id not in grouped:
                grouped[parent_id] = {}
            grouped[parent_id].setdefault(name, []).append(node)

        for group in grouped.values():
            method_nodes = group.get("method", [])
            path_nodes = group.get("route_path", [])
            middleware_nodes = group.get("middleware", [])
            handler_nodes = group.get("handler", [])

            if not method_nodes or not path_nodes:
                continue

            method = method_nodes[0].text.decode() if method_nodes[0].text else ""
            if method.lower() not in _EXPRESS_METHODS:
                continue

            raw_path = path_nodes[0].text.decode() if path_nodes[0].text else ""
            # Strip surrounding quotes
            route = raw_path.strip("'\"` ")
            if not route.startswith("/"):
                continue  # Not a route path (e.g. a string argument to app.set())

            middleware_names = [
                n.text.decode() for n in middleware_nodes if n.text
            ]
            handler_name = (
                handler_nodes[-1].text.decode()
                if handler_nodes and handler_nodes[-1].text
                else "<anonymous>"
            )

            routes.append(
                RouteInfo(
                    route_path=route,
                    http_methods=[method.upper()],
                    handler_file=file_path,
                    handler_name=handler_name,
                    middleware_names=middleware_names,
                )
            )

        return routes


# ---------------------------------------------------------------------------
# Regex fallback extractor (used when tree-sitter is unavailable)
# ---------------------------------------------------------------------------

# Matches: app.get('/path', mw1, mw2, handler)
#           router.post('/path', handler)
_ROUTE_RE = re.compile(
    r"""
    (?:app|router)\s*\.\s*
    (get|post|put|patch|delete|all|use)\s*\(
    \s*['"`]([^'"`]+)['"`]\s*     # route path
    ((?:\s*,\s*\w+)*)             # optional args (middleware + handler)
    """,
    re.VERBOSE | re.IGNORECASE,
)


class RegexExtractor:
    """Fallback route extractor using regular expressions."""

    def extract_routes(self, js_source: str, file_path: str) -> list[RouteInfo]:
        routes: list[RouteInfo] = []
        for match in _ROUTE_RE.finditer(js_source):
            method = match.group(1).upper()
            route = match.group(2)
            args_str = match.group(3)

            identifiers = [s.strip() for s in args_str.split(",") if s.strip()]
            handler_name = identifiers[-1] if identifiers else "<anonymous>"
            middleware_names = identifiers[:-1] if len(identifiers) > 1 else []

            routes.append(
                RouteInfo(
                    route_path=route,
                    http_methods=[method],
                    handler_file=file_path,
                    handler_name=handler_name,
                    middleware_names=middleware_names,
                )
            )
        return routes


def get_extractor() -> TreeSitterExtractor | RegexExtractor:
    """Return the best available extractor for this environment."""
    if _TREESITTER_AVAILABLE:
        return TreeSitterExtractor()
    return RegexExtractor()
