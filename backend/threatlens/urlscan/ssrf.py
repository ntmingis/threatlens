"""SSRF guard for any future server-side fetch.

ThreatLens v0.1 does NOT fetch submitted URLs. This guard exists so that the fetch feature, if added,
starts from a tested allow/deny decision. To resist DNS rebinding, a caller must connect to the IPs
returned here (pinning) and must call this again for every redirect hop.
Limitation: addresses embedded in NAT64/6to4 prefixes are not decoded.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable

from .parse import UrlError, parse_url


class SsrfBlocked(Exception):
    pass


def is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local
                                       or ip.is_private or ip.is_unspecified)


def _default_resolver(host: str) -> list[str]:
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


def resolve_and_check(url: str, resolver: Callable[[str], list[str]] = _default_resolver) -> list[str]:
    """Return the validated public IPs for the URL's host, or raise SsrfBlocked."""
    try:
        p = parse_url(url)
    except UrlError as e:
        raise SsrfBlocked(str(e)) from e
    if p["ip"]:
        ips = [p["ip"]]
    else:
        if p["host"] == "localhost" or p["host"].endswith((".localhost", ".local", ".internal")):
            raise SsrfBlocked(f"hostname {p['host']} is local")
        try:
            ips = resolver(p["host"])
        except OSError as e:
            raise SsrfBlocked(f"DNS resolution failed: {e}") from e
    if not ips:
        raise SsrfBlocked("hostname did not resolve")
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:  # one non-public answer is enough to refuse (blocks mixed A-record rebinding)
        raise SsrfBlocked(f"resolves to non-public address(es): {', '.join(bad)}")
    return ips
