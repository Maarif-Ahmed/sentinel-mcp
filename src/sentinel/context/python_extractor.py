"""
Python route extractor — Flask / FastAPI route and decorator analysis.

Bandit is a Python SAST scanner, but the Express.js extractor only parses
JavaScript, so a Bandit finding could never be attributed to a route: the two
halves of the pipeline operated on disjoint file sets. This module closes that
gap for the Python half.

SCOPE — the same two structural claims as the Express extractor:
  1. Which route a finding's file is reachable from
  2. Which decorators are applied to that route's handler

In Flask and FastAPI the stacked decorators on a handler occupy the same
position Express middleware does — they wrap the handler and run before it —
so they populate RouteInfo.middleware_names.

This does NOT claim that a decorator enforces authentication, that user input
flows to the finding, or that the finding is exploitable.

Parsing uses the stdlib `ast` module, so there is no build dependency.
"""

from __future__ import annotations

import ast
import re

from sentinel.context.extractor import RouteInfo

# Decorator attributes that register a route.
# 'route' takes an explicit methods= kwarg; the rest name the method directly.
_VERB_DECORATORS = {"get", "post", "put", "patch", "delete", "head", "options"}
_ROUTE_DECORATORS = {"route"} | _VERB_DECORATORS

# The decorator's receiver must look like an app, router or blueprint,
# otherwise unrelated decorators such as @cache.get("/key") are treated as
# route registrations.
_ROUTER_OBJECT_RE = re.compile(
    r"(^|[._])(app|router|blueprint|bp|api)s?$", re.IGNORECASE
)

# Constructors whose result is a routable object. Any local name assigned
# from one of these is treated as a router regardless of what it is called.
_ROUTER_FACTORIES = {"Flask", "Blueprint", "APIRouter", "FastAPI"}


def _is_router_object(name: str) -> bool:
    return bool(_ROUTER_OBJECT_RE.search(name.strip()))


def _dotted_name(node: ast.AST) -> str:
    """Render a Name/Attribute chain as dotted text; '' for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class PythonRouteExtractor:
    """Extracts Flask/FastAPI routes from Python source using the ast module."""

    def extract_routes(self, source: str, file_path: str) -> list[RouteInfo]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        router_names = self._find_router_names(tree)

        routes: list[RouteInfo] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_path: str | None = None
            http_methods: list[str] = []
            middleware: list[str] = []

            for decorator in node.decorator_list:
                parsed = self._parse_route_decorator(decorator, router_names)
                if parsed is None:
                    name = self._decorator_name(decorator)
                    if name:
                        middleware.append(name)
                else:
                    route_path, http_methods, route_deps = parsed
                    middleware.extend(route_deps)

            # FastAPI declares its guards as Depends() in the handler
            # signature rather than as stacked decorators, so a decorator-only
            # reading reports every FastAPI route as unauthenticated.
            middleware.extend(self._signature_dependencies(node))

            if route_path is not None:
                routes.append(
                    RouteInfo(
                        route_path=route_path,
                        http_methods=http_methods,
                        handler_file=file_path,
                        handler_name=node.name,
                        middleware_names=middleware,
                        handler_lines=(node.lineno, node.end_lineno or node.lineno),
                    )
                )
        return routes

    def _find_router_names(self, tree: ast.AST) -> set[str]:
        """Names bound to a Flask/Blueprint/APIRouter construction.

        Matching on the variable name alone misses the common Blueprint
        pattern, where the router is named after its feature — `admin =
        Blueprint(...)` then `@admin.route(...)`.
        """
        names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            ctor = _dotted_name(value.func).rsplit(".", 1)[-1]
            if ctor not in _ROUTER_FACTORIES:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        return names

    @staticmethod
    def _depends_name(node: ast.AST) -> str | None:
        """Name inside a Depends(...) call, e.g. Depends(verify_admin)."""
        if not isinstance(node, ast.Call):
            return None
        if _dotted_name(node.func).rsplit(".", 1)[-1] != "Depends":
            return None
        if not node.args:
            return None
        return _dotted_name(node.args[0]).rsplit(".", 1)[-1] or None

    def _signature_dependencies(self, node: ast.AST) -> list[str]:
        """Names from `param = Depends(guard)` defaults in the handler signature."""
        args = node.args
        defaults = list(args.defaults) + list(args.kw_defaults)
        found = []
        for default in defaults:
            if default is None:
                continue
            name = self._depends_name(default)
            if name:
                found.append(name)
        return found

    def _route_dependencies(self, decorator: ast.Call) -> list[str]:
        """Names from `dependencies=[Depends(guard), ...]` on the route decorator."""
        found = []
        for kw in decorator.keywords:
            if kw.arg != "dependencies" or not isinstance(kw.value, (ast.List, ast.Tuple)):
                continue
            for element in kw.value.elts:
                name = self._depends_name(element)
                if name:
                    found.append(name)
        return found

    def _parse_route_decorator(
        self, decorator: ast.AST, router_names: set[str] | None = None
    ) -> tuple[str, list[str], list[str]] | None:
        """Return (route_path, http_methods, dependency_names) for a route decorator."""
        if not isinstance(decorator, ast.Call):
            return None
        func = decorator.func
        if not isinstance(func, ast.Attribute) or func.attr not in _ROUTE_DECORATORS:
            return None

        receiver = _dotted_name(func.value)
        root = receiver.split(".")[0]
        known = router_names or set()
        if root not in known and receiver not in known:
            if not _is_router_object(receiver):
                return None

        if not decorator.args:
            return None
        first = decorator.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return None
        path = first.value
        if not path.startswith("/"):
            return None

        deps = self._route_dependencies(decorator)

        if func.attr in _VERB_DECORATORS:
            return path, [func.attr.upper()], deps

        # Flask's @app.route(..., methods=["GET", "POST"]); GET is the default.
        for kw in decorator.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [
                    el.value.upper()
                    for el in kw.value.elts
                    if isinstance(el, ast.Constant) and isinstance(el.value, str)
                ]
                if methods:
                    return path, methods, deps
        return path, ["GET"], deps

    def _decorator_name(self, decorator: ast.AST) -> str:
        """Name of a non-route decorator, e.g. 'login_required'."""
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return ""
