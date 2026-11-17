"""Ticket-triage HTTP API (standard library only).

    GET  /                  -> triage console (static HTML/CSS/JS from triage/static)
    GET  /health            -> 200 {"ok": true}
    POST /classify          {"text": "..."} -> 200 {"category", "urgency", "confidence"}
    POST /classify?explain=1   same, plus an "explanation" object (opt-in, for the console)

Production hygiene, all without dependencies:
* strict input validation with JSON error bodies (400 / 404 / 405 / 408 / 411 / 413 / 429)
* request-size cap, socket timeout, per-client token-bucket rate limit
* security headers, no-store caching, X-Request-ID on every response
* one-line JSON access log that never records ticket text or client addresses
* graceful shutdown on SIGTERM / Ctrl+C
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from triage.classifier import Triage, classify, explain

log = logging.getLogger("triage")

MAX_BODY_BYTES = 16 * 1024
MAX_DRAIN_BYTES = 1024 * 1024  # bodies above this are not read at all; the connection is just closed
SOCKET_TIMEOUT_S = 5
_REQUEST_ID_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")

# The console is a fixed set of files; requests are matched against this map, never joined onto a
# filesystem path, so there is no path traversal to defend against.
STATIC_DIR = Path(__file__).parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
_static_cache: dict[str, bytes] = {}


def static_file(path: str) -> bytes:
    if path not in _static_cache:
        _static_cache[path] = (STATIC_DIR / STATIC_FILES[path][0]).read_bytes()
    return _static_cache[path]


class RateLimiter:
    """Token bucket per client key. `capacity` = burst size, `rate` = tokens refilled per second."""

    def __init__(self, capacity: float, rate: float) -> None:
        self.capacity, self.rate = capacity, rate
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        if self.capacity <= 0:  # disabled
            return True
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            allowed = tokens >= 1
            self._buckets[key] = (tokens - 1 if allowed else tokens, now)
            if len(self._buckets) > 10_000:  # bound memory: drop idle (full) buckets
                self._buckets = {k: v for k, v in self._buckets.items() if v[0] < self.capacity}
            return allowed


class TriageHandler(BaseHTTPRequestHandler):
    server_version = "triage/1.0"
    sys_version = ""  # do not advertise the Python version
    protocol_version = "HTTP/1.1"

    # Injected by make_server(); class attributes so tests can swap them.
    limiter: RateLimiter = RateLimiter(capacity=300, rate=20)
    classifier = staticmethod(classify)

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(SOCKET_TIMEOUT_S)

    # ------------------------------------------------------------ responses

    def _send(self, status: int, data: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        self._write(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8", extra_headers)

    def _write(self, status: int, body: bytes, content_type: str, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Request-ID": self._request_id,
            **(extra_headers or {}),
        }
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._status = status

    def _error(self, status: int, code: str, message: str, extra_headers: dict[str, str] | None = None) -> None:
        # The request body may be unread (or half-read); closing keeps a keep-alive stream from desyncing.
        self.close_connection = True
        self._send(status, {"error": code, "message": message}, {"Connection": "close", **(extra_headers or {})})

    # ------------------------------------------------------------ routing

    def _handle(self) -> None:
        self._started = time.perf_counter()
        incoming = self.headers.get("X-Request-ID", "")
        self._request_id = incoming if 0 < len(incoming) <= 64 and set(incoming) <= _REQUEST_ID_OK else uuid.uuid4().hex
        self._status = 500
        path = self.path.split("?", 1)[0]
        try:
            if path in STATIC_FILES:
                if self.command in ("GET", "HEAD"):
                    return self._write(200, static_file(path), STATIC_FILES[path][1], {"Content-Security-Policy": PAGE_CSP})
                return self._error(405, "method_not_allowed", f"Use GET {path}.", {"Allow": "GET, HEAD"})
            if path == "/health":
                if self.command in ("GET", "HEAD"):
                    return self._send(200, {"ok": True})
                return self._error(405, "method_not_allowed", "Use GET /health.", {"Allow": "GET, HEAD"})
            if path == "/classify":
                if self.command == "POST":
                    return self._classify()
                return self._error(405, "method_not_allowed", "Use POST /classify.", {"Allow": "POST"})
            return self._error(404, "not_found", "Unknown path. Endpoints: GET /, GET /health, POST /classify.")
        except Exception:  # never leak a traceback to the client
            log.exception("unhandled error request_id=%s", self._request_id)
            if not self.wfile.closed:
                self._error(500, "internal_error", "Unexpected server error.")
        finally:
            self._access_log(path)

    def _classify(self) -> None:
        if not self.limiter.allow(self.client_address[0]):
            return self._error(429, "rate_limited", "Too many requests. Slow down.", {"Retry-After": "1"})
        # Content-Type is not enforced: `curl -d '{"text": ...}'` sends form-urlencoded, and the
        # body is validated as JSON below anyway, so rejecting it would only break honest clients.
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._error(411 if "Content-Length" not in self.headers else 400,
                               "invalid_length", "A valid Content-Length header is required.")
        if size <= 0:
            return self._error(400, "text_required", 'Body must be JSON like {"text": "..."}.')
        if size > MAX_BODY_BYTES:
            # Read and discard a moderately oversized body first: closing a socket with unread data
            # makes the OS send a reset, and the client would see a broken connection instead of 413.
            if size <= MAX_DRAIN_BYTES:
                self._discard(size)
            return self._error(413, "body_size", f"Body must be at most {MAX_BODY_BYTES} bytes.")
        try:
            data = json.loads(self.rfile.read(size).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._error(400, "invalid_json", "Body is not valid UTF-8 JSON.")
        except TimeoutError:
            self.close_connection = True
            return self._error(408, "request_timeout", "Request body was not received in time.")
        text = data.get("text") if isinstance(data, dict) else None
        if not isinstance(text, str) or not text.strip():
            return self._error(400, "text_required", '"text" must be a non-empty string.')
        query = parse_qs(self.path.partition("?")[2])
        if query.get("explain", [""])[0].lower() in ("1", "true", "yes"):
            return self._send(200, explain(text))  # evidence comes from the deterministic rules
        result: Triage = self.classifier(text)
        self._send(200, dict(result))

    def _discard(self, size: int) -> None:
        try:
            while size > 0:
                chunk = self.rfile.read(min(65536, size))
                if not chunk:
                    break
                size -= len(chunk)
        except OSError as exc:  # client went away mid-upload; the 413 is still attempted
            log.debug("drain aborted: %s", type(exc).__name__)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

    # ------------------------------------------------------------ logging

    def _access_log(self, path: str) -> None:
        # Deliberately no ticket text, query string or client address: tickets can hold personal data.
        log.info(json.dumps({
            "request_id": getattr(self, "_request_id", ""),
            "method": self.command,
            "path": path if path in STATIC_FILES or path in ("/health", "/classify") else "<other>",
            "status": self._status,
            "ms": round((time.perf_counter() - self._started) * 1000, 1),
        }))

    def log_message(self, format: str, *args: Any) -> None:
        # The default handler prints client IPs to stderr. Keep its messages (protocol errors) at
        # debug level, without the address, and rely on _access_log for normal traffic.
        log.debug(format, *args)


def make_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    TriageHandler.limiter = RateLimiter(
        capacity=float(os.getenv("RATE_LIMIT_BURST", "300")),
        rate=float(os.getenv("RATE_LIMIT_PER_SEC", "20")),
    )
    if os.getenv("TRIAGE_LLM", "").lower() in ("1", "true", "claude"):
        from triage.llm import classify_with_fallback

        TriageHandler.classifier = staticmethod(classify_with_fallback)
    server = ThreadingHTTPServer((host, port), TriageHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
    server = make_server(os.getenv("HOST", "0.0.0.0"), int(os.getenv("PORT", "8000")))

    def stop(*_: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    log.info(json.dumps({"event": "listening", "port": server.server_address[1]}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info(json.dumps({"event": "interrupted"}))
    finally:
        server.server_close()
        log.info(json.dumps({"event": "stopped"}))
