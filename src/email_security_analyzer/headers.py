"""Header analysis: detects spoofing and structural anomalies in email headers."""

from __future__ import annotations

import re
from email.message import Message
from email.utils import parsedate_to_datetime

from .addressing import domain_of_header, parse_first_address
from .models import HeaderFinding, Severity

# A short list of commonly impersonated brands used for display-name checks.
# Extend this list (or load from a config file) for production use.
COMMONLY_IMPERSONATED_BRANDS = [
    "microsoft", "paypal", "apple", "amazon", "google", "netflix",
    "bank of america", "wells fargo", "chase", "irs", "docusign",
    "office 365", "outlook", "linkedin", "facebook", "instagram",
]


def _record(
    findings: list[HeaderFinding],
    check: str,
    failed: bool,
    *,
    severity: Severity = Severity.INFO,
    weight: int = 0,
    fail_detail: str = "",
    pass_detail: str = "Check passed.",
) -> None:
    """Append a HeaderFinding for one check, covering both the fail and
    pass branches in a single call. Collapses the
    ``if condition: findings.append(HeaderFinding(..., passed=False, ...))
    else: findings.append(HeaderFinding(..., passed=True, ...))``
    pattern that used to be duplicated across every check below."""
    if failed:
        findings.append(
            HeaderFinding(check=check, passed=False, severity=severity, detail=fail_detail, weight=weight)
        )
    else:
        findings.append(
            HeaderFinding(check=check, passed=True, severity=Severity.INFO, detail=pass_detail)
        )


def analyze_headers(msg: Message) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []

    from_header = msg.get("From", "") or ""
    reply_to_header = msg.get("Reply-To", "") or ""
    return_path_header = msg.get("Return-Path", "") or ""
    message_id = msg.get("Message-ID", "") or ""

    from_name, _ = parse_first_address(from_header)
    from_domain = domain_of_header(from_header)

    # --- 1. From vs Reply-To mismatch -----------------------------------
    if reply_to_header:
        reply_domain = domain_of_header(reply_to_header)
        mismatch = bool(reply_domain and from_domain and reply_domain != from_domain)
        _record(
            findings,
            "from_reply_to_mismatch",
            mismatch,
            severity=Severity.HIGH,
            weight=15,
            fail_detail=(
                f"From domain '{from_domain}' does not match Reply-To domain "
                f"'{reply_domain}' — replies are redirected to a different party."
            ),
            pass_detail="Reply-To domain matches From domain (or not present).",
        )

    # --- 2. Return-Path vs From mismatch ---------------------------------
    if return_path_header:
        rp_domain = domain_of_header(return_path_header)
        mismatch = bool(rp_domain and from_domain and rp_domain != from_domain)
        _record(
            findings,
            "return_path_mismatch",
            mismatch,
            severity=Severity.MEDIUM,
            weight=10,
            fail_detail=(
                f"Return-Path domain '{rp_domain}' differs from From domain "
                f"'{from_domain}' — bounces go elsewhere."
            ),
            pass_detail="Return-Path domain matches From domain (or not present).",
        )

    # --- 3. Display-name brand impersonation ------------------------------
    lowered_name = from_name.lower()
    impersonated = next(
        (brand for brand in COMMONLY_IMPERSONATED_BRANDS if brand in lowered_name),
        None,
    )
    impersonation = bool(impersonated and impersonated not in from_domain)
    _record(
        findings,
        "display_name_impersonation",
        impersonation,
        severity=Severity.HIGH,
        weight=20,
        fail_detail=(
            f"Display name references '{impersonated}' but the sending domain "
            f"'{from_domain}' is unrelated — likely brand impersonation."
        ),
        pass_detail="No obvious brand impersonation in display name.",
    )

    # --- 4. Message-ID domain sanity check ---------------------------------
    mid_match = re.search(r"@([\w.-]+)", message_id)
    if mid_match:
        mid_domain = mid_match.group(1).lower()
        mismatch = bool(
            from_domain
            and mid_domain
            and not (
                mid_domain == from_domain
                or mid_domain.endswith("." + from_domain)
                or from_domain.endswith("." + mid_domain)
            )
        )
        if mismatch:
            findings.append(
                HeaderFinding(
                    check="message_id_domain_mismatch",
                    passed=False,
                    severity=Severity.LOW,
                    detail=(
                        f"Message-ID domain '{mid_domain}' is unrelated to From "
                        f"domain '{from_domain}'. Common with relays, but worth "
                        f"correlating with other signals."
                    ),
                    weight=5,
                )
            )

    # --- 5. Received chain anomalies ---------------------------------------
    received_headers = msg.get_all("Received", []) or []
    _record(
        findings,
        "received_chain",
        len(received_headers) == 0,
        severity=Severity.MEDIUM,
        weight=10,
        fail_detail="No Received headers present — unusual for a message that "
                     "traversed the internet; may be locally forged.",
        pass_detail=f"{len(received_headers)} Received hop(s) found.",
    )

    # --- 6. Date sanity (future-dated or missing) ---------------------------
    date_header = msg.get("Date")
    if not date_header:
        findings.append(
            HeaderFinding(
                check="date_header", passed=False, severity=Severity.LOW,
                detail="Missing Date header.", weight=5,
            )
        )
    else:
        try:
            parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            findings.append(
                HeaderFinding(
                    check="date_header", passed=False, severity=Severity.LOW,
                    detail=f"Malformed Date header: '{date_header}'.", weight=5,
                )
            )

    return findings
