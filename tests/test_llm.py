"""The LLM pass is tested with a fake client: no network, no API key, no cost."""

import json
from types import SimpleNamespace

from audit_agent import llm
from audit_agent.models import Category, Finding, ScanResult, Severity


def make_result() -> ScanResult:
    findings = [
        Finding("SEC001", "Hardcoded credential", Severity.CRITICAL, Category.SECURITY, "key", "a.py", 1),
        Finding("SEC002", "Possible hardcoded secret", Severity.HIGH, Category.SECURITY, "pw", "tests/b.py", 2),
        Finding("SLP009", "Debug print", Severity.LOW, Category.SLOP, "print", "c.py", 3),
    ]
    return ScanResult(root=".", files_scanned=3, findings=findings)


class FakeClient:
    def __init__(self, payload=None, stop_reason="end_turn", error=None):
        self.calls = []
        self._payload, self._stop, self._error = payload, stop_reason, error
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self._error:
            raise self._error
        text = json.dumps(self._payload)
        return SimpleNamespace(stop_reason=self._stop, content=[SimpleNamespace(type="text", text=text)])


VERDICTS = {
    "verdicts": [
        {"index": 0, "false_positive": True, "reason": "looks like a test key"},
        {"index": 1, "false_positive": True, "reason": "fixture password in a test"},
        {"index": 2, "false_positive": False, "reason": "stray debug output"},
    ],
    "summary": "1. Rotate the AWS key.",
}


def test_skipped_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = make_result()
    assert llm.is_available() is False
    assert llm.triage(result) is result


def test_triage_dismisses_false_positives_but_never_criticals():
    client = FakeClient(VERDICTS)
    out = llm.triage(make_result(), client=client)
    assert out.llm_used and out.summary.startswith("1.")
    assert [f.rule_id for f in out.findings] == ["SEC001", "SLP009"]  # critical kept despite the verdict
    assert out.findings[0].note == "looks like a test key"
    assert [f.rule_id for f in out.dismissed] == ["SEC002"]


def test_request_shape():
    client = FakeClient(VERDICTS)
    llm.triage(make_result(), client=client, model="claude-test")
    call = client.calls[0]
    assert call["model"] == "claude-test"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert '<finding index="2"' in call["messages"][0]["content"]
    assert "untrusted" in call["system"]


def test_api_failure_returns_original():
    result = make_result()
    assert llm.triage(result, client=FakeClient(error=RuntimeError("503"))) is result


def test_refusal_returns_original():
    result = make_result()
    assert llm.triage(result, client=FakeClient(VERDICTS, stop_reason="refusal")) is result


def test_findings_beyond_cap_pass_through(monkeypatch):
    monkeypatch.setattr(llm, "MAX_FINDINGS", 1)
    out = llm.triage(make_result(), client=FakeClient({"verdicts": [], "summary": "s"}))
    assert len(out.findings) == 3 and not out.dismissed
