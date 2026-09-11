"""Render an AnalysisResult as JSON or a human-readable text report."""

from __future__ import annotations

import json

from .models import AnalysisResult

_VERDICT_ICON = {"deliver": "PASS", "quarantine": "QUARANTINE", "reject": "REJECT"}


def to_json(result: AnalysisResult, indent: int = 2) -> str:
    return json.dumps(result.as_dict(), indent=indent)


def to_text(result: AnalysisResult) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("EMAIL SECURITY ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"Subject   : {result.subject}")
    lines.append(f"From      : {result.sender}")
    lines.append(f"Reply-To  : {result.reply_to or '(none)'}")
    lines.append("")

    lines.append("-- Header Analysis --")
    for f in result.header_findings:
        status = "OK" if f.passed else f"FLAG (+{f.weight})"
        lines.append(f"  [{status}] {f.check}: {f.detail}")

    lines.append("")
    lines.append("-- Authentication (SPF / DKIM / DMARC) --")
    for a in result.auth_results:
        lines.append(f"  [{a.mechanism.upper()}={a.result}] {a.detail}")

    if result.attachments:
        lines.append("")
        lines.append("-- Attachments --")
        for att in result.attachments:
            lines.append(f"  {att.filename} ({att.size_bytes} bytes, sha256={att.sha256[:16]}...)")
            for finding in att.findings:
                lines.append(f"      ! {finding}")
            if not att.findings:
                lines.append("      (no issues found)")

    if result.urls:
        lines.append("")
        lines.append("-- URLs --")
        for u in result.urls:
            lines.append(f"  {u.url}")
            for reason in u.reasons:
                lines.append(f"      ! {reason}")
            if not u.reasons:
                lines.append("      (no issues found)")

    if result.phishing_findings:
        lines.append("")
        lines.append("-- Phishing Content Indicators --")
        for p in result.phishing_findings:
            lines.append(f"  [{p.category}] (+{p.weight}) {p.detail}")

    if result.domain_age is not None and result.domain_age.result == "checked":
        lines.append("")
        lines.append("-- Domain Reputation --")
        lines.append(f"  {result.domain_age.detail}")

    lines.append("")
    lines.append("-- Risk Score --")
    for category, weight in result.risk.breakdown.items():
        lines.append(f"  {category:<20} +{weight}")
    lines.append(f"  {'TOTAL':<20} {result.risk.total}/100")
    lines.append("")
    lines.append(f"VERDICT: {_VERDICT_ICON[result.risk.verdict.value]} "
                  f"({result.risk.verdict.value.upper()})")
    lines.append("=" * 60)

    return "\n".join(lines)
