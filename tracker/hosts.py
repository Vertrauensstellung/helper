"""Hostname normalisation and scope checks."""
from __future__ import annotations

import re

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_host(value: str | None) -> str | None:
    """Return a canonical lowercase hostname or ``None`` if ``value`` is not one.

    Accepts things tools commonly emit: ``*.foo.com``, ``foo.com.``, ``https://foo.com:443/x``,
    ``FOO.com``. Rejects IPs, empty labels, spaces and anything non-hostname.
    """
    if not value:
        return None
    host = value.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):  # IPv6 literal
        return None
    host = host.split(":", 1)[0]
    while host.startswith("*."):
        host = host[2:]
    host = host.strip(".")
    if not host or len(host) > 253 or "." not in host:
        return None
    try:
        host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        return None
    labels = host.split(".")
    if not all(_LABEL.match(label) for label in labels):
        return None
    if labels[-1].isdigit():  # looks like an IPv4 address
        return None
    return host


def normalize_root(value: str | None) -> str | None:
    """Roots are taken literally: scope is the root itself plus everything below it."""
    return normalize_host(value)


def in_scope(host: str, root: str) -> bool:
    return host == root or host.endswith("." + root)


def parse_domain_list(text: str) -> list[str]:
    """Split comma/space/newline separated domain input, ignoring comments."""
    out = []
    for line in text.replace(",", "\n").splitlines():
        line = line.split("#", 1)[0].strip()
        for token in line.split():
            out.append(token)
    return out
