"""Coding gaps and loose ends: unfinished work, swallowed errors, missing tests and project files."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from audit_agent.models import Category, Finding, Severity
from audit_agent.rules.base import CODE, CSHARP, GO, JAVA, JS, PHP, PY, RUBY, FileRule, RegexRule, RepoRule, Rule, dotted_name
from audit_agent.workspace import Repo, SourceFile

G = Category.GAP


class TodoMarkerRule(FileRule):
    id = "GAP001"
    title = "Unresolved TODO/FIXME/HACK"
    severity = Severity.INFO
    category = G
    languages = CODE

    # Only markers inside a comment (#, //, /*, *, --, <!--) count; identifiers and strings do not.
    _rx = re.compile(r"(?:#|//|/\*|^\s*\*|--|<!--).*?\b(TODO|FIXME|HACK|XXX|BUG)\b")  # audit: ignore[GAP001]
    _weights = {"TODO": Severity.INFO, "FIXME": Severity.LOW, "HACK": Severity.LOW, "XXX": Severity.LOW, "BUG": Severity.LOW}

    def check(self, file: SourceFile) -> Iterator[Finding]:
        for lineno, line in enumerate(file.lines, start=1):
            m = self._rx.search(line)
            # Markers followed by "implement" are already reported by SLP001.
            if m and "implement" not in line.lower():
                yield self.finding(file.path, lineno, f"{m.group(1)} marker: {line.strip()[:120]}", line,
                                   severity=self._weights[m.group(1)])


class PythonErrorHandlingRule(FileRule):
    """Empty `except` bodies (GAP002) and bare `except:` clauses (GAP003)."""

    id = "GAP002"
    title = "Swallowed exception"
    severity = Severity.MEDIUM
    category = G
    languages = PY

    def check(self, file: SourceFile) -> Iterator[Finding]:
        tree = file.python_ast
        if tree is None:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            line = file.lines[node.lineno - 1]
            if all(_is_noop(s) for s in node.body):
                yield self.finding(file.path, node.lineno, "Exception is caught and silently ignored. Log it, handle it, or let it propagate.", line)
            elif node.type is None:
                yield Finding("GAP003", "Bare except", Severity.LOW, G,
                              "Bare `except:` also catches KeyboardInterrupt/SystemExit. Catch a specific exception.",
                              file.path, node.lineno, line.strip())


def _is_noop(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Pass) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))


class UnfinishedFunctionRule(FileRule):
    id = "GAP006"
    title = "Unfinished function"
    severity = Severity.MEDIUM
    category = G
    languages = PY
    include_tests = False

    _SKIP_DECORATORS = {"abstractmethod", "abstractproperty", "overload", "abc.abstractmethod", "typing.overload"}

    def check(self, file: SourceFile) -> Iterator[Finding]:
        tree = file.python_ast
        if tree is None:
            return
        protocol_classes = {
            id(fn)
            for cls in ast.walk(tree) if isinstance(cls, ast.ClassDef)
            and any(dotted_name(b).split(".")[-1] in {"Protocol", "ABC"} for b in cls.bases)
            for fn in cls.body
        }
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or id(node) in protocol_classes:
                continue
            if any(dotted_name(d) in self._SKIP_DECORATORS for d in node.decorator_list):
                continue
            body = node.body[1:] if _is_docstring(node.body[0]) else node.body
            line = file.lines[node.lineno - 1]
            if not body or all(isinstance(s, ast.Pass) or _is_ellipsis(s) for s in body):
                yield self.finding(file.path, node.lineno, f"`{node.name}()` has no implementation (only pass/.../docstring).", line)
            elif len(body) == 1 and _raises_not_implemented(body[0]):
                yield self.finding(file.path, node.lineno, f"`{node.name}()` only raises NotImplementedError.", line,
                                   severity=Severity.LOW)


def _is_docstring(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)


def _is_ellipsis(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


def _raises_not_implemented(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Raise) or stmt.exc is None:
        return False
    exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
    return dotted_name(exc) == "NotImplementedError"


class MissingTimeoutRule(FileRule):
    id = "GAP008"
    title = "Network call without timeout"
    severity = Severity.LOW
    category = G
    languages = PY
    include_tests = False

    _CALLS = {f"requests.{m}" for m in ("get", "post", "put", "patch", "delete", "head", "options", "request")} | {
        "urllib.request.urlopen", "urlopen"}

    def check(self, file: SourceFile) -> Iterator[Finding]:
        tree = file.python_ast
        if tree is None:
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and dotted_name(node.func) in self._CALLS:
                if not any(k.arg == "timeout" for k in node.keywords):
                    yield self.finding(file.path, node.lineno, "HTTP call has no timeout and can hang forever.",
                                       file.lines[node.lineno - 1])


def _regex_rules() -> list[RegexRule]:
    return [
        RegexRule("GAP002", "Swallowed exception", Severity.MEDIUM, G,
                  r"catch\s*(\([^)]*\))?\s*\{\s*\}|\.catch\(\s*\(?\s*\w*\s*\)?\s*=>\s*\{\s*\}\s*\)|if\s+err\s*!=\s*nil\s*\{\s*\}",
                  "Error is caught and silently ignored.", languages=JS | JAVA | CSHARP | PHP | GO),
        RegexRule("GAP006", "Unfinished function", Severity.LOW, G,
                  r"function\s+\w+\s*\([^)]*\)\s*\{\s*\}|=>\s*\{\s*\}\s*;?\s*$|throw new (Error\(\s*[\"']not implemented|NotImplementedException|UnsupportedOperationException\(\s*\))",
                  "Function body is empty or only throws 'not implemented'.", languages=JS | JAVA | CSHARP, include_tests=False),
        RegexRule("GAP007", "Error value discarded", Severity.MEDIUM, G,
                  r"^\s*_\s*=\s*[\w.]+\(|,\s*_\s*:?=\s*[\w.]+\(",
                  "Returned error is assigned to `_` and ignored.", languages=GO),
    ]


# --------------------------------------------------------------------------- repo-level

_TESTABLE = PY | JS | JAVA | GO | RUBY | PHP | CSHARP
_NOT_A_MODULE = re.compile(r"(^|/)(__init__|__main__|setup|conftest|manage|index|main|wsgi|asgi|settings|config)\.\w+$"
                           r"|(^|/)(docs?|examples?|scripts?|migrations|fixtures)/|\.d\.ts$|\.(config|conf)\.\w+$")


class MissingTestsRule(RepoRule):
    id = "GAP004"
    title = "Module without tests"
    severity = Severity.LOW
    category = G
    min_lines = 15

    def check(self, repo: Repo) -> Iterator[Finding]:
        sources = [f for f in repo.files if f.suffix in _TESTABLE and not f.is_test
                   and not _NOT_A_MODULE.search(f.path) and len(f.lines) >= self.min_lines]
        tests = [f for f in repo.files if f.is_test and f.suffix in _TESTABLE]
        if not sources:
            return
        if not tests:
            yield self.finding(".", 0, f"No test files found for {len(sources)} source modules.", severity=Severity.MEDIUM)
            return
        haystack = "\n".join(t.path.lower() + "\n" + t.text.lower() for t in tests)
        for f in sources:
            stem = PurePosixPath(f.path).stem.lower()
            if not re.search(rf"\b{re.escape(stem)}\b", haystack):
                yield self.finding(f.path, 0, f"No test file references `{stem}`.")


class MissingProjectFilesRule(RepoRule):
    id = "GAP005"
    title = "Missing project file"
    severity = Severity.LOW
    category = G

    _EXPECTED = [
        (("README*",), Severity.MEDIUM, "No README: nobody knows what this is or how to run it."),
        ((".gitignore",), Severity.LOW, "No .gitignore: build output and secrets are easy to commit by accident."),
        (("LICENSE*", "LICENCE*", "COPYING*"), Severity.LOW, "No LICENSE: the code is legally unusable by others."),
    ]

    def check(self, repo: Repo) -> Iterator[Finding]:
        if not repo.all_paths:
            return
        for names, severity, message in self._EXPECTED:
            if not repo.has_file(*names):
                yield self.finding(".", 0, message, severity=severity)


def rules() -> list[Rule]:
    return [TodoMarkerRule(), PythonErrorHandlingRule(), UnfinishedFunctionRule(), MissingTimeoutRule(),
            *_regex_rules(), MissingTestsRule(), MissingProjectFilesRule()]
