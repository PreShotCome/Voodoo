from __future__ import annotations

import platform
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


class PostureAuditor:
    """Portable, read-only checks. It never changes host configuration."""

    def run(self, data_root: Path) -> dict[str, object]:
        checks = [
            self._python(),
            self._tls(),
            self._data_permissions(data_root),
            self._hostname(),
        ]
        score = round(100 * sum(item.status == "pass" for item in checks) / len(checks))
        return {
            "host": platform.node(),
            "platform": platform.platform(),
            "score": score,
            "checks": [asdict(item) for item in checks],
        }

    def _python(self) -> Check:
        good = sys.version_info >= (3, 12)
        return Check(
            "python-version", "pass" if good else "warn", platform.python_version()
        )

    def _tls(self) -> Check:
        return Check("tls-runtime", "pass", ssl.OPENSSL_VERSION)

    def _data_permissions(self, root: Path) -> Check:
        try:
            mode = root.stat().st_mode & 0o777
        except OSError as exc:
            return Check("data-permissions", "warn", str(exc))
        if platform.system() == "Windows":
            return Check(
                "data-permissions", "info", "Review VoodooData ACLs with icacls"
            )
        good = not bool(mode & 0o077)
        return Check("data-permissions", "pass" if good else "warn", f"mode {mode:o}")

    def _hostname(self) -> Check:
        try:
            addresses = sorted(
                {item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None)}
            )
            return Check("host-addresses", "info", ", ".join(addresses))
        except socket.gaierror as exc:
            return Check("host-addresses", "warn", str(exc))
