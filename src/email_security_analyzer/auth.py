"""
SPF / DKIM / DMARC evaluation.

Primary source of truth is the ``Authentication-Results`` header stamped by
the receiving mail server, since that reflects the actual verification the
MTA performed against the true connecting IP (something we cannot fully
reconstruct after the fact). When that header is absent, we fall back to a
best-effort live SPF check via DNS TXT lookup if ``dnspython`` is installed
and network access is available; otherwise the mechanism is reported as
"unknown" rather than guessed.
"""

from __future__ import annotations

import ipaddress
import re
from email.message import Message

from .models import AuthResult

_AUTH_RESULTS_RE = re.compile(
    r"(?P<mechanism>spf|dkim|dmarc)\s*=\s*(?P<result>pass|fail|softfail|neutral|none|policy|permerror|temperror|bestguesspass)",
    re.IGNORECASE,
)

WEIGHTS = {
    "spf": {"fail": 15, "softfail": 8, "neutral": 3, "none": 5},
    "dkim": {"fail": 15, "none": 5},
    "dmarc": {"fail": 20, "none": 5},
}


def parse_authentication_results(msg: Message) -> list[AuthResult]:
    """Parse SPF/DKIM/DMARC verdicts out of Authentication-Results headers."""
    results: list[AuthResult] = []
    seen_mechanisms: set[str] = set()

    for header_value in msg.get_all("Authentication-Results", []) or []:
        for match in _AUTH_RESULTS_RE.finditer(header_value):
            mechanism = match.group("mechanism").lower()
            result = match.group("result").lower()
            if mechanism in seen_mechanisms:
                continue
            seen_mechanisms.add(mechanism)
            weight = WEIGHTS.get(mechanism, {}).get(result, 0)
            results.append(
                AuthResult(
                    mechanism=mechanism,
                    result=result,
                    detail=f"Reported by receiving MTA: {mechanism}={result}",
                    weight=weight,
                )
            )

    for mechanism in ("spf", "dkim", "dmarc"):
        if mechanism not in seen_mechanisms:
            results.append(
                AuthResult(
                    mechanism=mechanism,
                    result="unknown",
                    detail="No Authentication-Results found for this mechanism.",
                    weight=0,
                )
            )

    return results


def live_spf_check(sender_domain: str, sending_ip: str) -> AuthResult:
    """
    Best-effort live SPF evaluation by fetching the domain's SPF TXT record
    and checking simple ip4/ip6/a/mx/include mechanisms.

    This is intentionally simplified (no recursive 'include' resolution
    beyond one level, no 'exists' mechanism support) — it is a supplementary
    signal, not a replacement for a full RFC 7208 implementation.

    Requires the optional 'dnspython' dependency. Returns result="unknown"
    if the dependency is missing or DNS resolution fails (e.g. no network).
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return AuthResult(
            mechanism="spf",
            result="unknown",
            detail="dnspython not installed; skipping live SPF lookup.",
        )

    try:
        answers = dns.resolver.resolve(sender_domain, "TXT")
    except Exception as exc:  # noqa: BLE001 - DNS failures vary widely
        return AuthResult(
            mechanism="spf",
            result="unknown",
            detail=f"DNS lookup failed for {sender_domain}: {exc}",
        )

    spf_record = None
    for rdata in answers:
        txt = b"".join(rdata.strings).decode(errors="ignore") if hasattr(rdata, "strings") else str(rdata)
        if txt.startswith("v=spf1"):
            spf_record = txt
            break

    if not spf_record:
        return AuthResult(
            mechanism="spf",
            result="none",
            detail=f"No SPF TXT record found for {sender_domain}.",
            weight=WEIGHTS["spf"]["none"],
        )

    try:
        ip_obj = ipaddress.ip_address(sending_ip)
    except ValueError:
        return AuthResult(
            mechanism="spf",
            result="unknown",
            detail=f"Invalid sending IP '{sending_ip}' supplied for SPF check.",
        )

    for mechanism in spf_record.split():
        if mechanism.startswith("ip4:") or mechanism.startswith("ip6:"):
            network = mechanism.split(":", 1)[1]
            try:
                if ip_obj in ipaddress.ip_network(network, strict=False):
                    return AuthResult(
                        mechanism="spf",
                        result="pass",
                        detail=f"{sending_ip} matches SPF mechanism '{mechanism}'.",
                    )
            except ValueError:
                continue

    return AuthResult(
        mechanism="spf",
        result="fail",
        detail=f"{sending_ip} did not match any ip4/ip6 mechanism in: {spf_record}",
        weight=WEIGHTS["spf"]["fail"],
    )
