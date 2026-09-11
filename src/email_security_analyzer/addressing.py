"""Shared helpers for pulling a comparable domain out of an email address.

Extracted so header analysis (``headers.py``) and reputation lookups
(``reputation.py`` via the analyzer) agree on exactly how a domain is
derived from a ``From``/``Reply-To``/``Return-Path`` address, instead of
each module reimplementing the same string handling.
"""

from __future__ import annotations

from email.utils import getaddresses


def email_domain(address: str) -> str:
    """Return the lowercased domain portion of an email address, or ''.

    Tolerant of a trailing '>' left over from unparsed angle-address
    strings and of addresses with no '@' at all.
    """
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">")


def parse_first_address(header_value: str) -> tuple[str, str]:
    """Parse a raw header value (e.g. the 'From' header) and return the
    ``(display_name, address)`` of the first address found, or ``("", "")``
    if the header is empty or unparseable."""
    if not header_value:
        return "", ""
    addresses = getaddresses([header_value])
    return addresses[0] if addresses else ("", "")


def domain_of_header(header_value: str) -> str:
    """Convenience wrapper: raw header value -> domain of its first address."""
    _, address = parse_first_address(header_value)
    return email_domain(address)
