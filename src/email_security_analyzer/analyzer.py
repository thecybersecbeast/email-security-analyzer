"""Top-level orchestrator that runs every detector against an email and
produces a single AnalysisResult."""

from __future__ import annotations

import logging
from pathlib import Path

from .addressing import domain_of_header
from .attachments import analyze_attachment
from .auth import parse_authentication_results
from .headers import analyze_headers
from .models import AnalysisResult, DomainAgeResult
from .parser import get_body_text, iter_attachments, parse_eml_bytes, parse_eml_file
from .phishing import analyze_phishing_content
from .scoring import compute_risk_score
from .urls import analyze_urls

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """Runs the full detection pipeline against a single email message.

    Parameters
    ----------
    check_domain_age:
        When True, also look up the sender domain's WHOIS registration age
        as a supplementary risk signal (see ``reputation.py``). Off by
        default because it requires network access and the optional
        'whois' extra; corresponds to the CLI's ``--check-domain-age`` flag.
    """

    def __init__(self, check_domain_age: bool = False) -> None:
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

        domain_age = self._lookup_domain_age(sender) if self.check_domain_age else None

        risk = compute_risk_score(
            header_findings, auth_results, attachments, url_findings, phishing_findings, domain_age
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

    @staticmethod
    def _lookup_domain_age(sender_header: str) -> DomainAgeResult | None:
        # Imported lazily so the (optional, network-touching) reputation
        # module is only ever loaded when --check-domain-age is actually used.
        from .reputation import check_domain_age

        domain = domain_of_header(sender_header)
        if not domain:
            return None
        try:
            return check_domain_age(domain)
        except Exception:  # noqa: BLE001 - a reputation lookup must never fail the analysis
            logger.warning("Domain-age lookup failed for %r; continuing without it.", domain, exc_info=True)
            return None
