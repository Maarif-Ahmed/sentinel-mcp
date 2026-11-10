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
    # 1-indexed inclusive line span of the handler body, when the extractor
    # can determine it. Without this a finding is attributed to an arbitrary
    # route in the same file rather than the one it actually sits inside.
    handler_lines: tuple[int, int] | None = None


# ---------------------------------------------------------------------------
# Tree-sitter extractor (primary)
# ---------------------------------------------------------------------------

# Lazy import — tree-sitter may not build on all Windows configurations.
# If import fails, _TREESITTER_AVAILABLE is False and we use the regex fallback.
_TREESITTER_AVAILABLE = False

try:
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser, Query, QueryCursor

    _JS_LANGUAGE = Language(tsjs.language())
    _ts_parser = Parser(_JS_LANGUAGE)
    _TREESITTER_AVAILABLE = True
except Exception:
    pass

# Express HTTP method names we recognise as route registrations.
# 'use' is deliberately excluded: app.use('/assets', ...) mounts middleware or
# a sub-app, it does not register a request handler. Treating it as a route
# produced attributions like '/assets/public/images/padding'.
_EXPRESS_METHODS = {"get", "post", "put", "patch", "delete", "all"}

# The receiver of a route call must look like an Express app or router,
# otherwise unrelated calls such as cache.get("/key") are picked up as routes.
_ROUTER_OBJECT_RE = re.compile(r"(^|\.)(app|router)s?$", re.IGNORECASE)


def _is_router_object(text: str) -> bool:
    return bool(_ROUTER_OBJECT_RE.search(text.strip())) or "router" in text.lower()

# tree-sitter 0.26 API: Query + QueryCursor.matches() returns
# list of (pattern_index, dict[capture_name, list[Node]]) per match.
# We find route calls by matching on method name + first string argument.
_ROUTE_QUERY_PATTERN = """
(call_expression
  function: (member_expression
    object: (_) @object
    property: (property_identifier) @method)
  arguments: (arguments
    . (string) @route_path))
"""


class TreeSitterExtractor:
    """Extracts Express.js routes from JS/TS source using tree-sitter CST queries."""

    def extract_routes(self, js_source: str, file_path: str) -> list[RouteInfo]:
        if not _TREESITTER_AVAILABLE:
            raise RuntimeError("tree-sitter is not available")

        try:
            tree = _ts_parser.parse(js_source.encode())
            query = Query(_JS_LANGUAGE, _ROUTE_QUERY_PATTERN)
            cursor = QueryCursor(query)
            matches = cursor.matches(tree.root_node)
        except Exception:
            return []

        routes: list[RouteInfo] = []

        for _pattern_idx, cap_dict in matches:
            method_nodes = cap_dict.get("method", [])
            path_nodes = cap_dict.get("route_path", [])
            object_nodes = cap_dict.get("object", [])

            if not method_nodes or not path_nodes:
                continue

            method = method_nodes[0].text.decode() if method_nodes[0].text else ""
            if method.lower() not in _EXPRESS_METHODS:
                continue

            obj_text = (
                object_nodes[0].text.decode()
                if object_nodes and object_nodes[0].text
                else ""
            )
            if not _is_router_object(obj_text):
                continue

            raw_path = path_nodes[0].text.decode() if path_nodes[0].text else ""
            route = raw_path.strip("'\"` ")
            if not route.startswith("/"):
                continue

            # Parse middleware and handler from the arguments node directly.
            # Arguments: (path_string, [identifier...], handler)
            # Handler is the last arg; all identifier args before it are middleware.
            call_node = method_nodes[0].parent.parent  # member_expr → call_expr
            middleware_names, handler_name = self._parse_args(call_node)

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

    def _parse_args(self, call_node) -> tuple[list[str], str]:
        """Extract (middleware_names, handler_name) from a call_expression node."""
        args_node = call_node.child_by_field_name("arguments")
        if not args_node:
            return [], "<anonymous>"

        # Collect named children; skip the first (route path string)
        named = [c for c in args_node.named_children]
        if len(named) <= 1:
            return [], "<anonymous>"

        args_after_path = named[1:]  # skip path string
        handler_name = "<anonymous>"
        middleware_names: list[str] = []

        for child in args_after_path:
            if child.type == "identifier":
                middleware_names.append(child.text.decode())
            elif child.type in ("arrow_function", "function_expression", "function"):
                handler_name = "<anonymous>"
            # If last was identifier it's the handler, not middleware
        # The last identifier before an arrow/function is the handler
        # Re-classify: if the last arg is an identifier, that's the handler
        if args_after_path:
            last = args_after_path[-1]
            if last.type == "identifier" and last.text:
                handler_name = last.text.decode()
                middleware_names = [
                    c.text.decode()
                    for c in args_after_path[:-1]
                    if c.type == "identifier" and c.text
                ]

        return middleware_names, handler_name


# ---------------------------------------------------------------------------
# Regex fallback extractor (used when tree-sitter is unavailable)
# ---------------------------------------------------------------------------

# Matches: app.get('/path', mw1, mw2, handler)  or  app.get('/path', mw, (req,res)=>{})
# Group 1: method, Group 2: route path, Group 3: comma-separated identifiers,
# Group 4: presence of a trailing arrow/function expression (=> or function keyword)
_ROUTE_RE = re.compile(
    r"""
    (?:\w*(?:app|router)s?)\s*\.\s*
    (get|post|put|patch|delete|all)\s*\(
    \s*['"`]([^'"`]+)['"`]\s*     # route path
    ((?:\s*,\s*\w+)*)             # optional identifier args (middleware + named handler)
    (?:\s*,\s*(?:\(|function\b|async\s+(?:\(|function\b)))?  # trailing arrow/function?
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Separate pattern to detect if there's a trailing arrow/anonymous function argument
_TRAILING_ANON_RE = re.compile(
    r",\s*(?:async\s+)?(?:\([^)]*\)|[\w]+)\s*=>"
    r"|,\s*(?:async\s+)?function\s*\(",
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

            # Check if the source after this match has a trailing arrow/function.
            # If so, all captured identifiers are middleware (handler is anonymous).
            tail = js_source[match.start():]
            has_anon_handler = bool(_TRAILING_ANON_RE.search(tail[:300]))

            if has_anon_handler:
                # All identifiers are middleware; handler is the anonymous function
                middleware_names = identifiers
                handler_name = "<anonymous>"
            elif identifiers:
                # Last identifier is the named handler; rest are middleware
                handler_name = identifiers[-1]
                middleware_names = identifiers[:-1]
            else:
                handler_name = "<anonymous>"
                middleware_names = []

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
