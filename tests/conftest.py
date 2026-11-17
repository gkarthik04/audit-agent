from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from audit_agent.models import Finding
from audit_agent.rules.base import FileRule, RepoRule
from audit_agent.workspace import Repo, SourceFile, load_repo

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "messy_repo"


def src(path: str, text: str) -> SourceFile:
    return SourceFile(path, dedent(text).lstrip("\n"))


def run_file_rule(rule: FileRule, path: str, text: str) -> list[Finding]:
    file = src(path, text)
    return list(rule.check(file)) if rule.applies_to(file) else []


def repo_of(files: dict[str, str]) -> Repo:
    srcs = [src(p, t) for p, t in files.items()]
    return Repo(root=Path("."), files=srcs, all_paths=[s.path for s in srcs])


def run_repo_rule(rule: RepoRule, files: dict[str, str]) -> list[Finding]:
    return list(rule.check(repo_of(files)))


@pytest.fixture
def write_repo(tmp_path: Path):
    """Write {relative_path: content} to a temp dir and return the dir."""

    def _write(files: dict[str, str]) -> Path:
        for rel, text in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(dedent(text).lstrip("\n"), encoding="utf-8")
        return tmp_path

    return _write


@pytest.fixture(scope="session")
def fixture_repo() -> Repo:
    return load_repo(FIXTURE_REPO)
