from __future__ import annotations

import json
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import urljoin

import httpx

from voodoo.sentinel.correlator import Correlator
from voodoo.sentinel.detector import Detector
from voodoo.sentinel.guard import SentinelGuard
from voodoo.sentinel.models import Decision, Signal

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class ShieldProxy:
    def __init__(
        self,
        upstream: str,
        detector: Detector,
        correlator: Correlator,
        guard: SentinelGuard,
        mode: str = "divert",
        max_body: int = 1_048_576,
        rate_limit: int = 120,
    ):
        if not upstream.startswith(("http://", "https://")):
            raise ValueError("upstream must use http or https")
        self.upstream = upstream.rstrip("/") + "/"
        self.detector = detector
        self.correlator = correlator
        self.guard = guard
        self.mode = mode
        self.max_body = max_body
        self.rate_limit = rate_limit
        self._requests: dict[str, deque[datetime]] = defaultdict(deque)
        self._rate_lock = Lock()

    def _rate_decision(self, source_ip: str) -> Decision | None:
        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=60)
        with self._rate_lock:
            events = self._requests[source_ip]
            events.append(now)
            while events and events[0] < cutoff:
                events.popleft()
            count = len(events)
        if count <= self.rate_limit:
            return None
        signal = Signal.now(
            "request-flood", "high", source_ip, "HTTP request rate exceeded"
        )
        decision = Decision(
            self.mode,
            f"{count} requests inside 60 seconds",
            source_ip,
            signal.rule,
            count,
        )
        return self.guard.enforce(signal, decision)

    def serve(self, host: str, port: int) -> None:
        shield = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle()

            def do_HEAD(self):
                self._handle()

            def do_POST(self):
                self._handle()

            def do_PUT(self):
                self._handle()

            def do_DELETE(self):
                self._handle()

            def _handle(self):
                headers = {key.lower(): value for key, value in self.headers.items()}
                decisions = [
                    shield.guard.enforce(
                        signal, shield.correlator.evaluate(signal, shield.mode)
                    )
                    for signal in shield.detector.inspect_http(
                        self.path, headers, self.client_address[0]
                    )
                ]
                rate_decision = shield._rate_decision(self.client_address[0])
                if rate_decision:
                    decisions.append(rate_decision)
                action = (
                    "divert"
                    if any(item.action == "divert" for item in decisions)
                    else "block"
                    if any(item.action == "block" for item in decisions)
                    else "forward"
                )
                if action == "divert":
                    self._decoy()
                elif action == "block":
                    self.send_error(403, "Request refused")
                else:
                    self._forward()

            def _forward(self):
                length = int(self.headers.get("content-length", "0") or 0)
                if length > shield.max_body:
                    self.send_error(413, "Request too large")
                    return
                body = self.rfile.read(length) if length else None
                outbound = {
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() not in HOP_BY_HOP and k.lower() != "host"
                }
                try:
                    with httpx.Client(
                        follow_redirects=False, timeout=15, trust_env=False
                    ) as client:
                        response = client.request(
                            self.command,
                            urljoin(shield.upstream, self.path.lstrip("/")),
                            headers=outbound,
                            content=body,
                        )
                    self.send_response(response.status_code)
                    for key, value in response.headers.items():
                        if (
                            key.lower() not in HOP_BY_HOP
                            and key.lower() != "content-length"
                        ):
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(response.content)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(response.content)
                except httpx.HTTPError:
                    self.send_error(502, "Protected service unavailable")

            def _decoy(self):
                payload = json.dumps(
                    {"status": "accepted", "request_id": "pending"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            def log_message(self, format, *args):
                return

        ThreadingHTTPServer((host, port), Handler).serve_forever()
