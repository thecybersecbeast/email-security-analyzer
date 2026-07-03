"""Top-level orchestrator that runs every detector against an email and
produces a single AnalysisResult."""

from __future__ import annotations

from pathlib import Path

from .attachments import analyze_attachment
from .auth import parse_authentication_results
from .headers import analyze_headers
from .models import AnalysisResult
from .parser import get_body_text, iter_attachments, parse_eml_bytes, parse_eml_file
from .phishing import analyze_phishing_content
from .scoring import compute_risk_score
from .urls import analyze_urls


class EmailAnalyzer:
    """Runs the full detection pipeline against a single email message."""

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

        risk = compute_risk_score(
            header_findings, auth_results, attachments, url_findings, phishing_findings
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
        )
