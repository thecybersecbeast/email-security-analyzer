"""Rule-based phishing content detection (urgency, credential harvesting, impersonation)."""

from __future__ import annotations

import re

from .models import PhishingFinding, Severity

URGENCY_PATTERNS = [
    r"\bact now\b", r"\bact immediately\b", r"\burgent(ly)?\b",
    r"\bimmediate(ly)? action\b", r"\byour account (will be|has been) (closed|suspended|locked)\b",
    r"\bverify your account\b", r"\bconfirm your (identity|account|details)\b",
    r"\bwithin 24 hours\b", r"\blimited time\b", r"\bfinal notice\b",
    r"\bsuspicious activity\b", r"\bunauthoriz(ed|ation)\b",
]

CREDENTIAL_REQUEST_PATTERNS = [
    r"\bclick here to (login|log in|verify|update)\b",
    r"\bre-?enter your password\b",
    r"\benter your (password|ssn|social security|credit card|pin)\b",
    r"\bupdate your (billing|payment) (information|details)\b",
    r"\bconfirm your password\b",
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear customer\b", r"\bdear user\b", r"\bdear valued customer\b",
    r"\bdear account holder\b",
]


def _scan(patterns: list[str], text: str) -> list[str]:
    hits = []
    lowered = text.lower()
    for pattern in patterns:
        if re.search(pattern, lowered):
            hits.append(pattern.strip(r"\b"))
    return hits


def analyze_phishing_content(subject: str, body_text: str) -> list[PhishingFinding]:
    findings: list[PhishingFinding] = []
    combined = f"{subject}\n{body_text}"

    urgency_hits = _scan(URGENCY_PATTERNS, combined)
    if urgency_hits:
        findings.append(
            PhishingFinding(
                category="urgency_language",
                detail=f"Detected urgency/pressure phrasing ({len(urgency_hits)} match(es)), "
                       f"a common social-engineering tactic to short-circuit scrutiny.",
                severity=Severity.MEDIUM,
                weight=min(10 * len(urgency_hits), 20),
            )
        )

    credential_hits = _scan(CREDENTIAL_REQUEST_PATTERNS, combined)
    if credential_hits:
        findings.append(
            PhishingFinding(
                category="credential_harvesting",
                detail=f"Detected direct requests for credentials or a login click-through "
                       f"({len(credential_hits)} match(es)).",
                severity=Severity.HIGH,
                weight=min(15 * len(credential_hits), 30),
            )
        )

    greeting_hits = _scan(GENERIC_GREETING_PATTERNS, combined)
    if greeting_hits:
        findings.append(
            PhishingFinding(
                category="generic_greeting",
                detail="Uses a generic greeting instead of the recipient's name — "
                       "typical of mass-sent phishing campaigns.",
                severity=Severity.LOW,
                weight=5,
            )
        )

    return findings
