"""Combine weighted signals from every detector into a final risk score."""

from __future__ import annotations

from .models import (
    AttachmentInfo,
    AuthResult,
    HeaderFinding,
    PhishingFinding,
    RiskScore,
    URLFinding,
    Verdict,
)

# Verdict thresholds — tune these to your organization's risk appetite.
QUARANTINE_THRESHOLD = 40
REJECT_THRESHOLD = 70


def compute_risk_score(
    header_findings: list[HeaderFinding],
    auth_results: list[AuthResult],
    attachments: list[AttachmentInfo],
    urls: list[URLFinding],
    phishing_findings: list[PhishingFinding],
) -> RiskScore:
    breakdown: dict[str, int] = {}

    header_total = sum(f.weight for f in header_findings if not f.passed)
    if header_total:
        breakdown["headers"] = header_total

    auth_total = sum(a.weight for a in auth_results)
    if auth_total:
        breakdown["authentication"] = auth_total

    attachment_total = sum(a.weight for a in attachments)
    if attachment_total:
        breakdown["attachments"] = attachment_total

    url_total = sum(u.weight for u in urls)
    if url_total:
        breakdown["urls"] = url_total

    phishing_total = sum(p.weight for p in phishing_findings)
    if phishing_total:
        breakdown["phishing_content"] = phishing_total

    total = min(sum(breakdown.values()), 100)

    if total >= REJECT_THRESHOLD:
        verdict = Verdict.REJECT
    elif total >= QUARANTINE_THRESHOLD:
        verdict = Verdict.QUARANTINE
    else:
        verdict = Verdict.DELIVER

    return RiskScore(total=total, verdict=verdict, breakdown=breakdown)
