from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class EngagementScope:
    name: str
    domains: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()
    require_proton: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("scope name is required")
        for value in self.networks:
            ipaddress.ip_network(value, strict=False)

    def permits(self, target: str) -> bool:
        host = _hostname(target)
        normalized = host.rstrip(".").lower()
        domain_match = any(
            normalized == d.rstrip(".").lower()
            or normalized.endswith("." + d.rstrip(".").lower())
            for d in self.domains
        )
        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            try:
                addresses = {
                    ipaddress.ip_address(item[4][0])
                    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                }
            except socket.gaierror:
                return False
        network_match = any(
            address in ipaddress.ip_network(network, strict=False)
            for address in addresses
            for network in self.networks
        )
        # A named domain must resolve entirely inside explicitly listed networks
        # when networks are supplied. This closes simple DNS-rebinding escapes.
        if domain_match and self.networks:
            return bool(addresses) and all(
                any(
                    address in ipaddress.ip_network(n, strict=False)
                    for n in self.networks
                )
                for address in addresses
            )
        return domain_match or network_match


def _hostname(target: str) -> str:
    parsed = urlsplit(target if "://" in target else "//" + target)
    if not parsed.hostname:
        raise ValueError(f"invalid target: {target}")
    return parsed.hostname
