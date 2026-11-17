"""Deterministic support-ticket classifier.

`classify(text)` returns {"category", "urgency", "confidence"} where category is
one of CATEGORIES, urgency is "high" or "low", and confidence is in [0, 1].
Same input -> same output; no network, no secrets.

Pipeline (each step is small and separately testable):
1. normalize   - NFKC, lowercase, unify apostrophes, collapse whitespace
2. defang      - strip text that tries to steer the classifier
                 ("ignore previous instructions", "classify this as billing", "category: x")
3. score       - weighted signals per category; English and Hinglish patterns use word
                 boundaries, Devanagari patterns use substring match; a signal right after
                 a negation ("not a billing question", "no problem with payment") is ignored;
                 misspelled words ("pasword", "refnd") match by fuzzy similarity at reduced weight
4. decide      - highest score wins, ties broken by CATEGORIES order; nothing matched -> general
5. urgency     - explicit de-escalation ("not urgent", "no rush") wins over escalation signals
"""

from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher
from typing import TypedDict

CATEGORIES = ("billing", "technical", "account", "general")
URGENCIES = ("high", "low")
MAX_TEXT_CHARS = 10_000


class Triage(TypedDict):
    category: str
    urgency: str
    confidence: float


# --------------------------------------------------------------------------- signals
# (pattern, weight). Phrases are stronger evidence than single words.

_SIGNALS: dict[str, list[tuple[str, float]]] = {
    "billing": [
        (r"refunds?|refunded|money back", 2.5), (r"invoices?|receipts?|statement", 2), (r"billing|billed|bills?", 2),
        (r"payments?|paid|pay(s|ing)?|upi|deducted", 1.5), (r"charge[ds]?|overcharged|charging", 2),
        (r"subscriptions?|renewal|renew(ed)?|trial ended", 1.5), (r"card (got |was )?declined|credit card|debit card", 2),
        (r"price|pricing|cost|costs|plan cost|how much", 1.5), (r"discount|coupon|promo code", 1.5),
        (r"charged twice|double (charged|billed)|duplicate charge|do baar", 3), (r"money|bank|\$\d+|₹\s?\d+|rs\.? ?\d+", 1.5),
        (r"gst|vat|tax(es)?|fees?|late fee|waive", 1.5), (r"cancel(led)? (my )?(plan|subscription)|stop billing", 2),
        (r"can'?t pay|nobody can pay|unable to pay", 2.5), (r"paise|paisa|kat (gaye|gaya)", 2),
        ("रिफंड|पैसे|भुगतान|बिल", 2.5),
    ],
    "technical": [
        (r"errors?|exceptions?|stack ?trace", 1.5), (r"crash\w*|freez(e|es|ing)|frozen|hangs?", 2), (r"bugs?|buggy|glitch(es)?", 2),
        (r"broken|breaks", 1.5), (r"not working|doesn'?t work|does not work|stopped working|isn'?t working", 2),
        (r"fail(s|ed|ing|ure)?", 1), (r"time[ds]? ?out|timing out|timeouts?", 2), (r"slow|lag(gy|ging)?|takes forever", 1.5),
        (r"outage|(is|seems|went|site|app|platform|server) down|down for|stopped running", 2.5), (r"500|502|503|504|404|bad gateway", 1.5),
        (r"not loading|won'?t (load|open|start)|can'?t (load|open|connect)|blank (white )?screen|empty file", 2),
        (r"wrong (numbers|totals|data|values)|incorrect (data|totals|results)|no results|doesn'?t return", 2),
        (r"corrupt(ed|ion)?|lost (a|all|my|our)\b.*\b(work|data)|data loss|(is|are) gone", 2.5),
        (r"sync|webhooks?|integration|notifications?|api|server|database|upload|export", 1),
        (r"(since|after) (the |yesterday'?s |latest |last |recent )?update", 1.5), (r"vulnerabilit(y|ies)|exposes?", 2),
        (r"kaam nahi|nahi chal|band ho", 2), ("बंद हो|काम नहीं|त्रुटि|एरर", 2.5),
    ],
    "account": [
        (r"log ?in|logged (me )?out|sign ?in|signin|sign me in", 2), (r"passwords?", 2.5), (r"accounts?", 1.5),
        (r"usernames?|profile|phone number|email address|change (my )?email", 2),
        (r"locked out|lock(ed)? (my )?account|suspended|deactivated?", 2.5),
        (r"2fa|two[- ]factor|mfa|otp|verification code|authenticator|magic (login )?link", 2.5),
        (r"reset (my )?password|forgot (my )?password|password reset", 3), (r"verify|verification", 1),
        (r"delete my account|close my account|merge (my )?(two )?accounts|transfer ownership", 2.5),
        (r"teammates?|team members?|invite|workspace|admin|permissions?|access", 1),
        (r"hacked|someone logged into|unauthori[sz]ed login|changed my password", 2.5),
        (r"sign ?up|signed up|registered|sessions?|logs? me out|reset (email|link)|personal data|gdpr|credentials", 2), (r"email doesn'?t exist|email does not exist", 2),
        ("पासवर्ड|लॉगिन|खाता", 2.5),
    ],
    "general": [
        (r"feature request|suggestion|would (be|love) (great|nice)|would be great|consider adding|please add|it would be", 3),
        (r"thanks|thank you|love the|great service|awesome", 2), (r"hiring|careers?|job (openings?|vacanc(y|ies)|application)|internship", 2.5),
        (r"partner(ship)?|webinar|meetup|event|brochure|student program", 2.5),
        (r"office|opening hours|support hours|hours|address of|located", 1.5), (r"privacy policy|terms of service", 2.5),
    ],
}

# Single words used for typo tolerance ("pasword" ~ "password"). Only words of 5+ letters.
_FUZZY_VOCAB: dict[str, tuple[str, ...]] = {
    "billing": ("refund", "invoice", "payment", "charged", "billing", "subscription", "receipt", "discount"),
    "technical": ("crash", "crashing", "crashes", "error", "broken", "freezing", "loading", "timeout"),
    "account": ("password", "account", "username", "login", "verification", "profile"),
}
_FUZZY_RATIO = 0.84
_FUZZY_WEIGHT = 1.5
_FUZZY_MAX_WORDS = 300

# Text that tries to steer the classifier is removed before scoring (tickets are untrusted input).
_DEFANG = re.compile(
    r"(ignore|disregard|forget) (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules)[^.!?\n]*[.!?]?"
    r"|\b(classify|label|mark|categori[sz]e|tag|treat|route) (this|it|the ticket|me)?\s*(as|to|under)\s+[\w-]+"
    r"|\b(set|make) (the )?(urgency|priority|category) (to|as)\s+[\w-]+"
    r"|\b(category|urgency|priority)\s*[:=]\s*[\w-]+"
    r"|\b(system|assistant|developer)\s*:[^.!?\n]*[.!?]?"
)

_NEGATION_BEFORE = re.compile(
    r"(\bnot|\bno|\bisn'?t|\bwasn'?t|\bnothing to do with|\bnever had)\s+(an? |about |related to |really |problem with |issue with |issues with |problems with )*$"
)

_URGENT = re.compile(
    r"\b(urgent(ly)?|asap|as soon as possible|immediately|emergency|critical|sev ?1|p0)\b"
    r"|\b(outage|(is|seems|went|site|app|platform|server) down|down for|production|all customers|everyone|entire team|nobody can)\b"
    r"|\b(security|vulnerabilit(y|ies)|breach|hacked|compromised|fraud(ulent)?|someone logged into)\b"
    r"|\b(data loss|lost (a|all|my|our)\b.*\b(work|data)|corrupt(ed)?)\b"
    r"|\b(charged twice|double (charged|billed)|do baar|money (still )?left|left my bank)\b"
    r"|\b(locked out|can'?t access|cannot access|no access|blocked|losing (sales|money|customers|revenue))\b"
    r"|\b(lost my phone|starts in \d+ minutes|right now|can no longer (get in|log ?in|access))\b"
    r"|\b(unauthori[sz]ed (charge|transaction|payment)|charged (\d+|three|four|multiple|many) times)\b"
    r"|!!!|\bbad gateway\b|\b50[234]\b"
)
_MALFUNCTION = re.compile(
    r"\b(does nothing|doesn'?t|does not|didn'?t|won'?t|can'?t|cannot|unable|never (arrives?|delivered|shows?|loads?)"
    r"|wrong|incorrect|unreadable|stuck|forever|spinning|stopped|went wrong|no data|missing|disappear(ed|s)?"
    r"|nothing loads|not (showing|saving|updating|sent|delivered|running))\b"
)
_NOT_URGENT = re.compile(r"\b(not urgent|no rush|no hurry|whenever (you|convenient)|low priority|not a priority|when you get a chance)\b")


def _compile(pattern: str) -> re.Pattern[str]:
    # \b is unreliable around Devanagari vowel signs, so non-ASCII patterns match as substrings.
    return re.compile(pattern if not pattern.isascii() else rf"\b(?:{pattern})\b")


_COMPILED = {cat: [(_compile(p), w) for p, w in rules] for cat, rules in _SIGNALS.items()}


# --------------------------------------------------------------------------- pipeline

def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower().replace("’", "'").replace("‘", "'")
    return " ".join(text.split())


def defang(text: str) -> str:
    """Remove attempts to dictate the label; keep the actual problem description."""
    return _DEFANG.sub(" ", text)


def _negated(text: str, start: int) -> bool:
    return bool(_NEGATION_BEFORE.search(text[max(0, start - 40):start]))


def scores(text: str) -> dict[str, float]:
    t = defang(normalize(text))
    out = {cat: 0.0 for cat in CATEGORIES}
    matched_spans: list[tuple[int, int]] = []
    for cat, rules in _COMPILED.items():
        for rx, weight in rules:
            hit = next((m for m in rx.finditer(t) if not _negated(t, m.start())), None)
            if hit:
                out[cat] += weight
                matched_spans.append(hit.span())
    # Typo tolerance: a misspelled word ("pasword") adds evidence once per category, and only
    # if that category had no exact signal at all. Each distinct word is checked once, and the
    # number of words checked is capped so a 16 KB ticket stays fast.
    seen: set[str] = set()
    for m in re.finditer(r"[a-z]{5,}", t):
        word = m.group()
        if word in seen or len(seen) >= _FUZZY_MAX_WORDS:
            continue
        seen.add(word)
        if any(s <= m.start() < e for s, e in matched_spans) or _negated(t, m.start()):
            continue
        cat = _fuzzy_category(word)
        if cat and out[cat] == 0:
            out[cat] = _FUZZY_WEIGHT
    return out


def _fuzzy_category(word: str) -> str | None:
    for cat, vocab in _FUZZY_VOCAB.items():
        for v in vocab:
            if word != v and abs(len(word) - len(v)) <= 2 and SequenceMatcher(None, word, v).ratio() >= _FUZZY_RATIO:
                return cat
    return None


def urgency(text: str) -> str:
    t = defang(normalize(text))
    if _NOT_URGENT.search(t):
        return "low"
    return "high" if _URGENT.search(t) else "low"


def classify(text: str) -> Triage:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    text = text[:MAX_TEXT_CHARS]
    s = scores(text)
    ranked = sorted(s.items(), key=lambda kv: (-kv[1], CATEGORIES.index(kv[0])))
    (best, top), (_, second) = ranked[0], ranked[1]
    if top == 0:
        # No topical signal. A ticket describing something going wrong is most likely a product
        # fault; anything else (greetings, questions, feedback) is general.
        if _MALFUNCTION.search(defang(normalize(text))):
            return {"category": "technical", "urgency": urgency(text), "confidence": 0.45}
        return {"category": "general", "urgency": urgency(text), "confidence": 0.4}
    margin = (top - second) / top  # 1.0 = unambiguous, 0.0 = tie
    confidence = min(0.95, 0.45 + 0.07 * top + 0.25 * margin)
    return {"category": best, "urgency": urgency(text), "confidence": round(confidence, 2)}
