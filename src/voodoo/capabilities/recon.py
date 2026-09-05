from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from voodoo.core.ledger import EventLedger
from voodoo.security.policy import PolicyEngine


@dataclass(frozen=True)
class PortResult:
    port: int
    open: bool
    service: str | None = None


class Recon:
    def __init__(
        self,
        policy: PolicyEngine,
        ledger: EventLedger,
        max_ports: int = 128,
        concurrency: int = 32,
    ):
        self.policy = policy
        self.ledger = ledger
        self.max_ports = max_ports
        self.concurrency = concurrency

    async def scan(
        self, scope: str, host: str, ports: list[int], timeout: float = 1.0
    ) -> list[PortResult]:
        self.policy.authorize(scope, "recon.scan", host)
        ports = sorted(set(ports))
        if (
            not ports
            or len(ports) > self.max_ports
            or any(p < 1 or p > 65535 for p in ports)
        ):
            raise ValueError(f"provide 1 to {self.max_ports} valid ports")
        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe(port: int) -> PortResult:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return PortResult(port, True, _service(port))
                except (OSError, TimeoutError):
                    return PortResult(port, False)

        results = await asyncio.gather(*(probe(port) for port in ports))
        self.ledger.append(
            "recon.scan.completed",
            {
                "scope": scope,
                "host": host,
                "ports": ports,
                "open": [asdict(x) for x in results if x.open],
            },
        )
        return results

    async def headers(self, scope: str, url: str) -> dict[str, object]:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL scheme must be http or https")
        self.policy.authorize(scope, "recon.http", url)
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=10, trust_env=False
        ) as client:
            async with client.stream(
                "GET", url, headers={"User-Agent": "Voodoo/0.2 authorized-audit"}
            ) as response:
                status = response.status_code
                headers = _redacted_headers(response.headers)
        report = {
            "status": status,
            "headers": headers,
            "security": _security_headers(headers),
        }
        self.ledger.append(
            "recon.http.completed",
            {"scope": scope, "url": url, "status": status},
        )
        return report

    def certificate(self, scope: str, host: str, port: int = 443) -> dict[str, object]:
        self.policy.authorize(scope, "recon.tls", host)
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
                cipher = wrapped.cipher()
        report = {
            "subject": dict(x[0] for x in cert.get("subject", ())),
            "issuer": dict(x[0] for x in cert.get("issuer", ())),
            "sans": [
                value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"
            ],
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "cipher": cipher[0] if cipher else None,
            "checked_at": datetime.now(UTC).isoformat(),
        }
        self.ledger.append(
            "recon.tls.completed", {"scope": scope, "host": host, "port": port}
        )
        return report


def _service(port: int) -> str | None:
    try:
        return socket.getservbyport(port)
    except OSError:
        return None


def _redacted_headers(headers: httpx.Headers) -> dict[str, str]:
    sensitive = {"set-cookie", "authorization", "proxy-authorization"}
    return {
        name: "[redacted]" if name.lower() in sensitive else value
        for name, value in headers.items()
    }


def _security_headers(headers: dict[str, str]) -> dict[str, bool]:
    expected = (
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    )
    return {name: name in headers for name in expected}
