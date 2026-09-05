from __future__ import annotations

import ipaddress
import re

from voodoo.sentinel.models import Signal

IP = re.compile(r"(?<![\w:])((?:\d{1,3}\.){3}\d{1,3})(?![\w:])")
RULES = (
    (
        "credential-attack",
        "high",
        re.compile(
            r"(?i)(failed password|login failed|invalid user|authentication failure)"
        ),
    ),
    ("web-traversal", "high", re.compile(r"(?i)(?:\.\./|%2e%2e|/etc/passwd|win\.ini)")),
    (
        "web-secret-probe",
        "high",
        re.compile(r"(?i)(?:/\.env|/\.git/|/server-status|/actuator/env)"),
    ),
    (
        "web-injection",
        "high",
        re.compile(r"(?i)(?:union(?:\s|%20)+select|<script|%3cscript|\$\{jndi:)"),
    ),
    (
        "suspicious-command",
        "medium",
        re.compile(
            r"(?i)(?:powershell.+-(?:enc|encodedcommand)|frombase64string|certutil.+-decode)"
        ),
    ),
    (
        "control-disabled",
        "critical",
        re.compile(
            r"(?i)(?:antivirus|firewall|audit(?:ing)?).{0,30}(?:disabled|stopped|cleared)"
        ),
    ),
)


class Detector:
    def inspect_line(self, line: str) -> list[Signal]:
        source = _source_ip(line)
        return [
            Signal.now(name, severity, source, line.strip())
            for name, severity, pattern in RULES
            if pattern.search(line)
        ]

    def inspect_http(
        self, path: str, headers: dict[str, str], source_ip: str
    ) -> list[Signal]:
        material = f"{source_ip} {path} {headers.get('user-agent', '')}"
        return self.inspect_line(material)


def _source_ip(line: str) -> str | None:
    for match in IP.finditer(line):
        try:
            return str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            continue
    return None
