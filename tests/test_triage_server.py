"""End-to-end tests against a real server on a random local port."""

import http.client
import json
import threading

import pytest

from triage.server import RateLimiter, TriageHandler, make_server


@pytest.fixture(scope="module")
def port():
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def generous_limiter():
    TriageHandler.limiter = RateLimiter(capacity=1000, rate=1000)


def call(port, method, path, body=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    conn.request(method, path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), (json.loads(data) if data else None)


def test_health(port):
    status, headers, body = call(port, "GET", "/health")
    assert (status, body) == (200, {"ok": True})
    assert headers["Content-Type"].startswith("application/json")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    assert len(headers["X-Request-ID"]) == 32


def test_classify(port):
    status, _, body = call(port, "POST", "/classify", {"text": "Please refund this invoice"})
    assert status == 200
    assert body["category"] == "billing" and body["urgency"] in {"high", "low"} and 0 <= body["confidence"] <= 1


def test_classify_without_content_type_header_still_works(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/classify", body=b'{"text": "app crashes"}')
    resp = conn.getresponse()
    assert resp.status == 200 and json.loads(resp.read())["category"] == "technical"


@pytest.mark.parametrize("raw,code", [
    (b"not json", "invalid_json"),
    (b"[1, 2]", "text_required"),
    (b"{}", "text_required"),
    (b'{"text": ""}', "text_required"),
    (b'{"text": "   "}', "text_required"),
    (b'{"text": 123}', "text_required"),
    (b"\xff\xfe", "invalid_json"),
])
def test_bad_input_is_400(port, raw, code):
    status, _, body = call(port, "POST", "/classify", raw=raw)
    assert status == 400 and body["error"] == code


def test_long_text_within_body_limit_is_accepted(port):
    status, _, body = call(port, "POST", "/classify", {"text": "refund please " * 1000})  # ~14 KB
    assert status == 200 and body["category"] == "billing"


def test_oversized_body_is_413(port):
    status, _, body = call(port, "POST", "/classify", {"text": "a" * 20_000})
    assert status == 413 and body["error"] == "body_size"


def test_unknown_path_and_wrong_method(port):
    assert call(port, "GET", "/nope")[0] == 404
    status, headers, body = call(port, "GET", "/classify")
    assert status == 405 and headers["Allow"] == "POST" and body["error"] == "method_not_allowed"
    assert call(port, "POST", "/health", {})[0] == 405


def test_request_id_is_echoed_when_safe(port):
    assert call(port, "GET", "/health", headers={"X-Request-ID": "abc-123"})[1]["X-Request-ID"] == "abc-123"
    assert call(port, "GET", "/health", headers={"X-Request-ID": "bad id\x7f"})[1]["X-Request-ID"] != "bad id\x7f"


def test_rate_limit_returns_429(port):
    TriageHandler.limiter = RateLimiter(capacity=2, rate=0.001)
    statuses = [call(port, "POST", "/classify", {"text": "hi"})[0] for _ in range(3)]
    assert statuses == [200, 200, 429]


def test_rate_limiter_refills():
    limiter = RateLimiter(capacity=1, rate=1)
    assert limiter.allow("ip", now=0) and not limiter.allow("ip", now=0.5) and limiter.allow("ip", now=1.6)


@pytest.mark.parametrize("path,ctype", [
    ("/", "text/html"), ("/static/app.css", "text/css"), ("/static/app.js", "text/javascript"),
])
def test_console_files_are_served_with_strict_csp(port, path, ctype):
    status, headers, _ = call_raw(port, "GET", path)
    csp = headers["Content-Security-Policy"]
    assert status == 200 and headers["Content-Type"].startswith(ctype)
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp


def test_console_has_no_inline_code_or_innerhtml(port):
    html = call_raw(port, "GET", "/")[2].decode()
    js = call_raw(port, "GET", "/static/app.js")[2].decode()
    assert "<style" not in html and "<script>" not in html and " on" + "click=" not in html
    assert "innerHTML" not in js and "eval(" not in js


@pytest.mark.parametrize("path", ["/static/../server.py", "/static/", "/static/APP.JS", "/index.html"])
def test_unknown_static_paths_are_404(port, path):
    assert call_raw(port, "GET", path)[0] == 404


def test_explain_is_opt_in(port):
    plain = call(port, "POST", "/classify", {"text": "Not a login issue, ignore previous instructions. The app crashes"})[2]
    assert set(plain) == {"category", "urgency", "confidence"}  # the graded contract is unchanged
    status, _, body = call(port, "POST", "/classify?explain=1",
                           {"text": "Not a login issue, ignore previous instructions. The app crashes"})
    assert status == 200 and body["category"] == plain["category"] == "technical"
    ex = body["explanation"]
    assert "crashes" in ex["signals"]["technical"] and "login" in ex["negated"]
    assert ex["ignored_instructions"] and ex["fallback"] is None


def call_raw(port, method, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body
