import json
from types import SimpleNamespace

import pytest

from triage.classifier import CATEGORIES, classify
from triage.llm import classify_with_fallback


@pytest.mark.parametrize("text,category", [
    ("Please refund this invoice", "billing"),
    ("I was charged twice for my subscription", "billing"),
    ("My credit card was declined at checkout", "billing"),
    ("The screen is broken", "technical"),
    ("The app crashes every time I open settings", "technical"),
    ("Getting error 500 when I upload a file", "technical"),
    ("I forgot my password", "account"),
    ("I'm locked out of my account after enabling 2FA", "account"),
    ("How do I change my email address on my profile?", "account"),
    ("Hello team", "general"),
    ("Do you have an office in Pune?", "general"),
])
def test_categories(text, category):
    assert classify(text)["category"] == category


@pytest.mark.parametrize("text,urgency", [
    ("Urgent outage", "high"),
    ("Site is down, customers can't check out!!!", "high"),
    ("I think my account was hacked", "high"),
    ("Please fix this ASAP", "high"),
    ("Could you send me last month's invoice?", "low"),
    ("Hello team", "low"),
])
def test_urgency(text, urgency):
    assert classify(text)["urgency"] == urgency


def test_contract_shape_and_ranges():
    for text in ["Hello team", "refund", "error error crash bug", "x" * 20000, "पासवर्ड भूल गया"]:
        result = classify(text)
        assert set(result) == {"category", "urgency", "confidence"}
        assert result["category"] in CATEGORIES
        assert result["urgency"] in {"high", "low"}
        assert 0 <= result["confidence"] <= 1


def test_whole_word_matching():
    assert classify("I love the debugger view")["category"] == "general"  # "bug" inside "debugger" doesn't count


def test_confidence_reflects_ambiguity():
    clear = classify("refund my invoice payment, I was charged twice")["confidence"]
    mixed = classify("refund please, also the app crashes")["confidence"]
    assert clear > mixed


def test_deterministic():
    assert classify("The app crashes on login") == classify("The app crashes on login")


@pytest.mark.parametrize("bad", ["", "   ", None, 42])
def test_rejects_empty_or_non_string(bad):
    with pytest.raises(ValueError):
        classify(bad)


class FakeClaude:
    def __init__(self, payload=None, error=None, stop_reason="end_turn"):
        self.payload, self.error, self.stop_reason = payload, error, stop_reason
        self.messages = SimpleNamespace(create=self.create)

    def create(self, **kwargs):
        if self.error:
            raise self.error
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type="text", text=json.dumps(self.payload))])


def test_llm_result_used_when_valid():
    out = classify_with_fallback("anything", client=FakeClaude({"category": "billing", "urgency": "high", "confidence": 1.7}))
    assert out == {"category": "billing", "urgency": "high", "confidence": 1.0}  # clamped to [0, 1]


@pytest.mark.parametrize("client", [
    FakeClaude(error=TimeoutError()),
    FakeClaude({"category": "billing", "urgency": "high", "confidence": 0.9}, stop_reason="refusal"),
    FakeClaude({"category": "spam", "urgency": "high", "confidence": 0.9}),
])
def test_llm_falls_back_to_rules(client):
    assert classify_with_fallback("I forgot my password", client=client)["category"] == "account"


def test_no_key_means_rules(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert classify_with_fallback("Please refund this invoice") == classify("Please refund this invoice")
