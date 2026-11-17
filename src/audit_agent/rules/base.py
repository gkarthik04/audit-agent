"""Rule contracts.

A rule is a small object with an `id`, `title`, `severity`, `category` and a
`check` method. There are three flavours, chosen by what the rule needs to see:

* `FileRule`  - sees one file at a time (most rules).
* `RegexRule` - a `FileRule` defined declaratively by a line regex. No code needed.
* `RepoRule`  - sees the whole repository (cross-file checks, missing files).

Python-only AST rules are just `FileRule`s with `languages = {".py"}` that read
`file.python_ast`.
"""

from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass

from audit_agent.models import Category, Finding, Severity
from audit_agent.workspace import Repo, SourceFile


class Rule(ABC):
    id: str
    title: str
    severity: Severity
    category: Category

    def finding(
        self,
        path: str,
        line: int = 0,
        message: str | None = None,
        snippet: str = "",
        severity: Severity | None = None,
    ) -> Finding:
        """Helper so rules only supply what varies per hit."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity or self.severity,
            category=self.category,
            message=message or self.title,
            path=path,
            line=line,
            snippet=snippet.strip()[:200],
        )


class FileRule(Rule):
    #: file suffixes this rule applies to; empty = every text file
    languages: frozenset[str] = frozenset()
    #: whether test files are scanned (e.g. debug prints in tests are fine)
    include_tests: bool = True
    #: skip prose (README, docs) - right for code patterns, wrong for secrets
    skip_docs: bool = False

    def applies_to(self, file: SourceFile) -> bool:
        if file.is_test and not self.include_tests:
            return False
        if self.skip_docs and file.suffix in DOCS:
            return False
        return not self.languages or file.suffix in self.languages

    @abstractmethod
    def check(self, file: SourceFile) -> Iterator[Finding]: ...


class RepoRule(Rule):
    @abstractmethod
    def check(self, repo: Repo) -> Iterator[Finding]: ...


@dataclass
class RegexRule(FileRule):
    """Declarative line-based rule: flag every line matching `pattern`."""

    id: str
    title: str
    severity: Severity
    category: Category
    pattern: str
    message: str = ""
    languages: frozenset[str] = frozenset()
    include_tests: bool = True
    skip_docs: bool = False
    flags: int = 0
    #: lines that also match this pattern are skipped (cheap false-positive filter)
    unless: str | None = None

    def __post_init__(self) -> None:
        self._rx = re.compile(self.pattern, self.flags)
        self._unless = re.compile(self.unless, self.flags) if self.unless else None

    def check(self, file: SourceFile) -> Iterator[Finding]:
        for lineno, line in enumerate(file.lines, start=1):
            if self._rx.search(line) and not (self._unless and self._unless.search(line)):
                yield self.finding(file.path, lineno, self.message or self.title, line)


# Common language groups, so rules read naturally: `languages=JS | TS`.
PY = frozenset({".py"})
JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
JAVA = frozenset({".java", ".kt", ".scala"})
GO = frozenset({".go"})
RUBY = frozenset({".rb"})
PHP = frozenset({".php"})
CSHARP = frozenset({".cs"})
CODE = PY | JS | JAVA | GO | RUBY | PHP | CSHARP | frozenset(
    {".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".swift", ".sh", ".bash", ".ps1", ".lua", ".r", ".pl"}
)
DOCS = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc", ".html"})


def dotted_name(node: ast.AST) -> str:
    """`a.b.c(...)` -> "a.b.c"; anything else -> ""."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""
