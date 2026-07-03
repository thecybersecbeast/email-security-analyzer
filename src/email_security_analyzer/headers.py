"""Header analysis: detects spoofing and structural anomalies in email headers."""

from __future__ import annotations

import re
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

from .models import HeaderFinding, Severity

# A short list of commonly impersonated brands used for display-name checks.
# Extend this list (or load from a config file) for production use.
COMMONLY_IMPERSONATED_BRANDS = [
    "microsoft", "paypal", "apple", "amazon", "google", "netflix",
    "bank of america", "wells fargo", "chase", "irs", "docusign",
    "office 365", "outlook", "linkedin", "facebook", "instagram",
]


def _domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">")


def analyze_headers(msg: Message) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []

    from_header = msg.get("From", "") or ""
    reply_to_header = msg.get("Reply-To", "") or ""
    return_path_header = msg.get("Return-Path", "") or ""
    message_id = msg.get("Message-ID", "") or ""

    from_addrs = getaddresses([from_header])
    from_name, from_addr = from_addrs[0] if from_addrs else ("", "")
    from_domain = _domain_of(from_addr)

    # --- 1. From vs Reply-To mismatch -----------------------------------
    if reply_to_header:
        reply_addrs = getaddresses([reply_to_header])
        reply_name, reply_addr = reply_addrs[0] if reply_addrs else ("", "")
        reply_domain = _domain_of(reply_addr)
        if reply_domain and from_domain and reply_domain != from_domain:
            findings.append(
                HeaderFinding(
                    check="from_reply_to_mismatch",
                    passed=False,
                    severity=Severity.HIGH,
                    detail=(
                        f"From domain '{from_domain}' does not match "
                        f"Reply-To domain '{reply_domain}' — replies are "
                        f"redirected to a different party."
                    ),
                    weight=15,
                )
            )
        else:
            findings.append(
                HeaderFinding(
                    check="from_reply_to_mismatch",
                    passed=True,
                    severity=Severity.INFO,
                    detail="Reply-To domain matches From domain (or not present).",
                )
            )

    # --- 2. Return-Path vs From mismatch ---------------------------------
    if return_path_header:
        rp_addrs = getaddresses([return_path_header])
        _, rp_addr = rp_addrs[0] if rp_addrs else ("", "")
        rp_domain = _domain_of(rp_addr)
        if rp_domain and from_domain and rp_domain != from_domain:
            findings.append(
                HeaderFinding(
                    check="return_path_mismatch",
                    passed=False,
                    severity=Severity.MEDIUM,
                    detail=(
                        f"Return-Path domain '{rp_domain}' differs from "
                        f"From domain '{from_domain}' — bounces go elsewhere."
                    ),
                    weight=10,
                )
            )
        else:
            findings.append(
                HeaderFinding(
                    check="return_path_mismatch",
                    passed=True,
                    severity=Severity.INFO,
                    detail="Return-Path domain matches From domain (or not present).",
                )
            )

    # --- 3. Display-name brand impersonation ------------------------------
    lowered_name = from_name.lower()
    impersonated = next(
        (brand for brand in COMMONLY_IMPERSONATED_BRANDS if brand in lowered_name),
        None,
    )
    if impersonated and impersonated not in from_domain:
        findings.append(
            HeaderFinding(
                check="display_name_impersonation",
                passed=False,
                severity=Severity.HIGH,
                detail=(
                    f"Display name references '{impersonated}' but the sending "
                    f"domain '{from_domain}' is unrelated — likely brand "
                    f"impersonation."
                ),
                weight=20,
            )
        )
    else:
        findings.append(
            HeaderFinding(
                check="display_name_impersonation",
                passed=True,
                severity=Severity.INFO,
                detail="No obvious brand impersonation in display name.",
            )
        )

    # --- 4. Message-ID domain sanity check ---------------------------------
    mid_match = re.search(r"@([\w.-]+)", message_id)
    if mid_match:
        mid_domain = mid_match.group(1).lower()
        if from_domain and mid_domain and not (
            mid_domain == from_domain
            or mid_domain.endswith("." + from_domain)
            or from_domain.endswith("." + mid_domain)
        ):
            findings.append(
                HeaderFinding(
                    check="message_id_domain_mismatch",
                    passed=False,
                    severity=Severity.LOW,
                    detail=(
                        f"Message-ID domain '{mid_domain}' is unrelated to "
                        f"From domain '{from_domain}'. Common with relays, "
                        f"but worth correlating with other signals."
                    ),
                    weight=5,
                )
            )

    # --- 5. Received chain anomalies ---------------------------------------
    received_headers = msg.get_all("Received", []) or []
    if len(received_headers) == 0:
        findings.append(
            HeaderFinding(
                check="received_chain",
                passed=False,
                severity=Severity.MEDIUM,
                detail="No Received headers present — unusual for a message "
                       "that traversed the internet; may be locally forged.",
                weight=10,
            )
        )
    else:
        findings.append(
            HeaderFinding(
                check="received_chain",
                passed=True,
                severity=Severity.INFO,
                detail=f"{len(received_headers)} Received hop(s) found.",
            )
        )

    # --- 6. Date sanity (future-dated or missing) ---------------------------
    date_header = msg.get("Date")
    if not date_header:
        findings.append(
            HeaderFinding(
                check="date_header",
                passed=False,
                severity=Severity.LOW,
                detail="Missing Date header.",
                weight=5,
            )
        )
    else:
        try:
            parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            findings.append(
                HeaderFinding(
                    check="date_header",
                    passed=False,
                    severity=Severity.LOW,
                    detail=f"Malformed Date header: '{date_header}'.",
                    weight=5,
                )
            )

    return findings
