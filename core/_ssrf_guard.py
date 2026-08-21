"""
Central SSRF guard shared by the egress proxy (and available to any other
component that needs to resolve an operator-configured or sandbox-supplied
hostname).

Design contract
---------------
`resolve_public_endpoints(host)` returns a list of (family, ip) tuples for
every A / AAAA record the resolver returns, EXCLUDING any address in a
private / reserved / link-local range. If the result is empty (all
addresses were private, or the name failed to resolve), the caller MUST
refuse the connection.

The important guarantee — the one that closes the pre-existing DNS-
rebinding TOCTOU — is:

  * DNS is resolved ONCE.
  * The caller connects to a specific `ip` string, NOT the hostname.
  * A subsequent DNS record change cannot substitute a private IP for the
    connect() step, because the connect() step no longer resolves.

Both IPv4 (A) and IPv6 (AAAA) are handled. The pre-existing implementation
used `socket.gethostbyname` which only inspected the first A record; an
attacker with a public A + private AAAA passed the SSRF check and then the
kernel preferred the AAAA at connect time.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import List, Tuple

# Address ranges that must NEVER be reachable through the egress proxy.
# Both v4 and v6 covered. Additions to this list should be conservative:
# something surfacing here means an operator config bug was contained.
_PRIVATE_NETS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),           # "this network"
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),         # loopback
    ipaddress.ip_network("169.254.0.0/16"),      # link-local incl. cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),        # IETF assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),       # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # multicast
    ipaddress.ip_network("240.0.0.0/4"),         # reserved
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    # IPv6
    ipaddress.ip_network("::/128"),              # unspecified
    ipaddress.ip_network("::1/128"),             # loopback
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped -> re-check as v4
    ipaddress.ip_network("64:ff9b::/96"),        # NAT64
    ipaddress.ip_network("100::/64"),            # discard-only
    ipaddress.ip_network("2001::/23"),           # IETF protocol assignments
    ipaddress.ip_network("2001:db8::/32"),       # documentation
    ipaddress.ip_network("fc00::/7"),            # ULA
    ipaddress.ip_network("fe80::/10"),           # link-local
    ipaddress.ip_network("ff00::/8"),            # multicast
]


class SSRFBlocked(Exception):
    """Raised when a hostname resolves only to disallowed addresses."""

    def __init__(self, hostname: str, blocked: List[str]) -> None:
        super().__init__(
            f"SSRF guard: {hostname!r} resolves only to disallowed addresses "
            f"{blocked!r} (or is unresolvable)"
        )
        self.hostname = hostname
        self.blocked = blocked


def _is_disallowed(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # malformed — reject

    # IPv4-mapped IPv6 (::ffff:1.2.3.4) — re-classify against IPv4 tables.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped

    for net in _PRIVATE_NETS:
        if addr.version != net.version:
            continue
        if addr in net:
            return True
    return False


async def resolve_public_endpoints(
    hostname: str,
    port: int,
    *,
    resolver: "callable | None" = None,
) -> List[Tuple[int, str, int]]:
    """Resolve `hostname` and return only addresses that are NOT in the
    disallowed set. Each result is (address_family, ip_string, port).

    A caller wanting to connect must use these tuples exactly — NEVER pass
    the hostname back to a connect() call, or a second DNS lookup opens
    the TOCTOU window this function exists to close.

    `resolver` is dependency-injected to enable deterministic testing; if
    None, the asyncio event-loop's non-blocking getaddrinfo is used.

    Raises:
        SSRFBlocked — hostname has no acceptable address.
    """
    import asyncio

    try:
        if resolver is not None:
            # Synchronous injection path used by tests.
            infos = resolver(hostname, port, type=socket.SOCK_STREAM)
        else:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
    except (socket.gaierror, OSError):
        raise SSRFBlocked(hostname, [])

    acceptable: List[Tuple[int, str, int]] = []
    rejected: List[str] = []
    seen: set = set()
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET:
            ip = sockaddr[0]
        elif family == socket.AF_INET6:
            ip = sockaddr[0]
        else:
            continue

        if ip in seen:
            continue
        seen.add(ip)

        if _is_disallowed(ip):
            rejected.append(ip)
            continue
        acceptable.append((family, ip, port))

    if not acceptable:
        raise SSRFBlocked(hostname, rejected)
    return acceptable
