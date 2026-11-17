# audit: ignore-file -- these tests deliberately contain the patterns the rules detect.
from collections.abc import Iterator

import pytest

from audit_agent.engine import dedupe, run_rules, scan
from audit_agent.models import Category, Finding, Severity
from audit_agent.rules.base import FileRule
from audit_agent.workspace import load_repo
from conftest import FIXTURE_REPO, repo_of


class ExplodingRule(FileRule):
    id, title, severity, category = "TST001", "boom", Severity.LOW, Category.GAP

    def check(self, file) -> Iterator[Finding]:
        raise RuntimeError("bug in rule")


def test_inline_suppression(write_repo):
    root = write_repo({"a.py": """
        h = hashlib.md5(x)  # audit: ignore
        h = hashlib.md5(x)  # audit: ignore[SEC999]
        h = hashlib.md5(x)  # audit: ignore[SEC006]
        h = hashlib.md5(x)
    """})
    hits = [f for f in scan(root).findings if f.rule_id == "SEC006"]
    assert [f.line for f in hits] == [2, 4]


def test_file_level_suppression(write_repo):
    root = write_repo({
        "a.py": "# audit: ignore-file[SEC]\nh = hashlib.md5(x)\nimport os\n",
        "b.py": "h = hashlib.md5(x)\n",
    })
    hits = {(f.path, f.rule_id) for f in scan(root).findings}
    assert ("a.py", "SEC006") not in hits and ("a.py", "SLP006") in hits and ("b.py", "SEC006") in hits


def test_disable_by_prefix_also_drops_sibling_ids(write_repo):
    root = write_repo({"a.py": "import subprocess\nsubprocess.run(c, shell=True)\n"})
    assert any(f.rule_id == "SEC004" for f in scan(root).findings)
    assert not any(f.rule_id.startswith("SEC") for f in scan(root, disable={"SEC"}).findings)


def test_min_severity_filters(write_repo):
    root = write_repo({"a.py": "import os\n"})
    assert all(f.severity.rank >= Severity.MEDIUM.rank for f in scan(root, min_severity=Severity.MEDIUM).findings)


def test_crashing_rule_does_not_break_scan():
    with pytest.warns(UserWarning, match="TST001"):
        assert run_rules(repo_of({"a.py": "x = 1"}), [ExplodingRule()]) == []


def test_dedupe_keeps_distinct_messages():
    a = Finding("X", "t", Severity.LOW, Category.GAP, "one", ".")
    b = Finding("X", "t", Severity.LOW, Category.GAP, "two", ".")
    assert dedupe([a, a, b]) == [a, b]


def test_walker_skips_vendor_binary_and_ignored(write_repo):
    root = write_repo({
        "src/a.py": "x = 1",
        "node_modules/lib/index.js": "eval(x)",
        "generated/out.py": "eval(x)",
        "src/pkg.egg-info/PKG-INFO": "eval(x)",
        ".auditignore": "generated/\n",
    })
    (root / "img.png").write_bytes(b"\x89PNG\x00\x00binary")
    repo = load_repo(root)
    assert sorted(f.path for f in repo.files) == [".auditignore", "src/a.py"]


def test_findings_sorted_by_severity():
    result = scan(FIXTURE_REPO)
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_fixture_repo_end_to_end():
    """The messy fixture exercises every rule family; this guards against silent regressions."""
    result = scan(FIXTURE_REPO)
    found = {f.rule_id for f in result.findings}
    expected = {
        "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008", "SEC009", "SEC010",
        "SLP001", "SLP002", "SLP003", "SLP004", "SLP005", "SLP006", "SLP007", "SLP008", "SLP009", "SLP010",
        "GAP001", "GAP002", "GAP003", "GAP004", "GAP005", "GAP006", "GAP007", "GAP008",
    }
    assert expected <= found, f"missing: {sorted(expected - found)}"
    assert result.counts()["critical"] >= 1
