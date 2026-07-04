"""Top-level orchestrator that runs every detector against an email and
produces a single AnalysisResult."""

from __future__ import annotations

from email.utils import parseaddr
from pathlib import Path

from .attachments import analyze_attachment
from .auth import parse_authentication_results
from .headers import analyze_headers
from .models import AnalysisResult
from .parser import get_body_text, iter_attachments, parse_eml_bytes, parse_eml_file
from .phishing import analyze_phishing_content
from .reputation import check_domain_age
from .scoring import compute_risk_score
from .urls import analyze_urls


class EmailAnalyzer:
    """Runs the full detection pipeline against a single email message.

    Parameters
    ----------
    check_domain_age:
        If True, performs a live WHOIS lookup on the sender's domain and
        factors registration age into the risk score. Off by default
        since it requires network access and the optional 'whois'
        dependency; silently degrades to no-op if either is unavailable.
    """

    def __init__(self, check_domain_age: bool = False):
        self.check_domain_age = check_domain_age

    def analyze_file(self, path: str | Path) -> AnalysisResult:
        msg = parse_eml_file(path)
        return self._analyze_message(msg)

    def analyze_bytes(self, data: bytes) -> AnalysisResult:
        msg = parse_eml_bytes(data)
        return self._analyze_message(msg)

    def _analyze_message(self, msg) -> AnalysisResult:
        subject = msg.get("Subject", "") or ""
        sender = msg.get("From", "") or ""
        reply_to = msg.get("Reply-To")

        body_text = get_body_text(msg)

        header_findings = analyze_headers(msg)
        auth_results = parse_authentication_results(msg)

        attachments = [
            analyze_attachment(filename, content_type, data)
            for filename, content_type, data in iter_attachments(msg)
        ]

        url_findings = analyze_urls(body_text)
        phishing_findings = analyze_phishing_content(subject, body_text)

        domain_age = None
        reputation_weight = 0
        if self.check_domain_age:
            _, sender_addr = parseaddr(sender)
            sender_domain = sender_addr.rsplit("@", 1)[-1] if "@" in sender_addr else ""
            domain_age = check_domain_age(sender_domain)
            reputation_weight = domain_age.weight

        risk = compute_risk_score(
            header_findings, auth_results, attachments, url_findings,
            phishing_findings, reputation_weight=reputation_weight,
        )

        return AnalysisResult(
            subject=subject,
            sender=sender,
            reply_to=reply_to,
            header_findings=header_findings,
            auth_results=auth_results,
            attachments=attachments,
            urls=url_findings,
            phishing_findings=phishing_findings,
            risk=risk,
            domain_age=domain_age,
        )
