import json

import pytest

from audit_agent.cli import main
from audit_agent.engine import scan
from audit_agent.reporters import render
from conftest import FIXTURE_REPO


@pytest.fixture(scope="module")
def result():
    return scan(FIXTURE_REPO)


def test_json_report_roundtrips(result):
    data = json.loads(render(result, "json"))
    assert len(data["findings"]) == len(result.findings)
    assert data["counts"]["critical"] == result.counts()["critical"]
    assert {"rule_id", "severity", "category", "path", "line", "message"} <= data["findings"][0].keys()


def test_sarif_report_is_valid_shape(result):
    doc = json.loads(render(result, "sarif"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert len(run["results"]) == len(result.findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert all(r["level"] in {"error", "warning", "note"} for r in run["results"])


@pytest.mark.parametrize("fmt,marker", [("text", "== Security issues"), ("markdown", "## Security issues")])
def test_human_formats(result, fmt, marker):
    assert marker in render(result, fmt)


def test_unknown_format(result):
    with pytest.raises(ValueError):
        render(result, "xml")


class TestCli:
    def test_fail_on_threshold(self, capsys):
        assert main(["scan", str(FIXTURE_REPO), "--no-llm", "--fail-on", "critical"]) == 1
        assert "SEC001" in capsys.readouterr().out

    def test_clean_repo_passes(self, write_repo):
        root = write_repo({"README.md": "# x", ".gitignore": "", "LICENSE": "MIT", "a.py": "X = 1\n"})
        assert main(["scan", str(root), "--no-llm", "--fail-on", "info"]) == 0

    def test_output_file(self, tmp_path):
        out = tmp_path / "report.json"
        assert main(["scan", str(FIXTURE_REPO), "--no-llm", "-f", "json", "-o", str(out)]) == 0
        assert json.loads(out.read_text(encoding="utf-8"))["findings"]

    def test_missing_path(self, tmp_path):
        assert main(["scan", str(tmp_path / "nope"), "--no-llm"]) == 2

    def test_rules_listing(self, capsys):
        assert main(["rules"]) == 0
        out = capsys.readouterr().out
        assert "SEC001" in out and "SLP005" in out and "GAP004" in out
