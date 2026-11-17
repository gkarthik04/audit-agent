"""Repository discovery: which files exist, their text, and cheap derived facts.

This is the only module that touches the filesystem. Rules receive `SourceFile`
and `Repo` objects, which makes them trivial to unit-test with in-memory data.
"""

from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path, PurePosixPath

# Directories that are never worth scanning (vendored, generated, or VCS internals).
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "__pycache__",
    ".venv", "venv", "env", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "target", "out", ".next", ".idea", ".vscode", "coverage", ".gradle",
}
MAX_FILE_BYTES = 1_000_000
IGNORE_FILE = ".auditignore"

TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs", "testing"}


@dataclass
class SourceFile:
    """One text file in the repo. `path` is POSIX and relative to the repo root."""

    path: str
    text: str

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.path).suffix.lower()

    @property
    def is_python(self) -> bool:
        return self.suffix == ".py"

    @cached_property
    def is_test(self) -> bool:
        p = PurePosixPath(self.path.lower())
        if any(part in TEST_DIR_NAMES for part in p.parts[:-1]):
            return True
        n = p.name
        return (
            n.startswith("test_")
            or n == "conftest.py"
            or any(m in n for m in ("_test.", ".test.", ".spec.", "_spec."))
            or (p.stem.endswith("test") and p.suffix in {".java", ".kt", ".cs"})
        )

    @cached_property
    def python_ast(self) -> ast.Module | None:
        """Parsed AST for Python files, or None if not Python / not parseable."""
        if not self.is_python:
            return None
        try:
            return ast.parse(self.text, filename=self.path)
        except (SyntaxError, ValueError):
            return None


@dataclass
class Repo:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    all_paths: list[str] = field(default_factory=list)  # includes binary / oversized files

    def get(self, path: str) -> SourceFile | None:
        return self._by_path.get(path)

    @cached_property
    def _by_path(self) -> dict[str, SourceFile]:
        return {f.path: f for f in self.files}

    def has_file(self, *names: str) -> bool:
        """True if any top-level file matches one of `names` (case-insensitive, glob ok)."""
        top = [p for p in self.all_paths if "/" not in p]
        return any(fnmatch.fnmatch(p.lower(), n.lower()) for p in top for n in names)


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def _load_ignore_patterns(root: Path, extra: list[str]) -> list[str]:
    patterns = list(extra)
    ignore_file = root / IGNORE_FILE
    if ignore_file.is_file():
        for raw in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def _ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def load_repo(root: str | Path, exclude: list[str] | None = None) -> Repo:
    """Walk `root` and load every reasonably sized text file."""
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    patterns = _load_ignore_patterns(root_path, exclude or [])
    repo = Repo(root=root_path)

    for path in sorted(root_path.rglob("*")):
        rel_parts = path.relative_to(root_path).parts
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in rel_parts[:-1]) or not path.is_file():
            continue
        rel = PurePosixPath(*rel_parts).as_posix()
        if _ignored(rel, patterns):
            continue
        repo.all_paths.append(rel)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if _is_binary(data):
            continue
        repo.files.append(SourceFile(rel, data.decode("utf-8", errors="replace")))
    return repo
