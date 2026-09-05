from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class VPNState:
    connected: bool
    provider: str
    interface: str | None
    evidence: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class ProtonVPNGuard:
    """Read-only Proton tunnel detection. It never starts or reconfigures the VPN."""

    def inspect(self) -> VPNState:
        override = os.getenv("VOODOO_PROTON_INTERFACE", "").strip()
        if override:
            names = self._interface_names()
            connected = override.casefold() in {name.casefold() for name in names}
            return VPNState(
                connected, "proton", override, "operator-pinned active interface"
            )
        system = platform.system()
        if system == "Windows":
            return self._windows()
        if system == "Linux":
            return self._linux()
        return VPNState(
            False, "proton", None, f"automatic detection unsupported on {system}"
        )

    def require(self) -> VPNState:
        state = self.inspect()
        if not state.connected:
            raise RuntimeError("this scope requires an active Proton VPN tunnel")
        return state

    def _interface_names(self) -> list[str]:
        if platform.system() == "Windows":
            state = self._windows()
            return [state.interface] if state.interface else []
        try:
            return [item for item in os.listdir("/sys/class/net")]
        except OSError:
            return []

    def _windows(self) -> VPNState:
        script = (
            "Get-NetAdapter -IncludeHidden | Where-Object Status -eq 'Up' | "
            "Select-Object Name,InterfaceDescription | ConvertTo-Json -Compress"
        )
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=8,
                check=True,
            )
            raw = json.loads(completed.stdout or "[]")
            adapters = raw if isinstance(raw, list) else [raw]
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            return VPNState(
                False, "proton", None, f"adapter check failed: {type(exc).__name__}"
            )
        for adapter in adapters:
            label = (
                f"{adapter.get('Name', '')} {adapter.get('InterfaceDescription', '')}"
            )
            if "proton" in label.casefold():
                return VPNState(
                    True,
                    "proton",
                    str(adapter.get("Name")),
                    "active Proton-named adapter",
                )
        return VPNState(False, "proton", None, "no active Proton-named adapter")

    def _linux(self) -> VPNState:
        try:
            completed = subprocess.run(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "NAME,TYPE,DEVICE",
                    "connection",
                    "show",
                    "--active",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            for line in completed.stdout.splitlines():
                if "proton" in line.casefold():
                    device = line.rsplit(":", 1)[-1] or None
                    return VPNState(
                        True,
                        "proton",
                        device,
                        "active Proton NetworkManager connection",
                    )
        except (OSError, subprocess.SubprocessError):
            pass
        for name in self._interface_names():
            if "proton" in name.casefold():
                try:
                    state = (
                        open(f"/sys/class/net/{name}/operstate", encoding="utf-8")
                        .read()
                        .strip()
                    )
                except OSError:
                    continue
                if state in {"up", "unknown"}:
                    return VPNState(
                        True, "proton", name, "active Proton-named interface"
                    )
        return VPNState(False, "proton", None, "no active Proton connection detected")
