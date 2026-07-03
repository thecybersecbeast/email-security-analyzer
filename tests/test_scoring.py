from email_security_analyzer.models import (
    AttachmentInfo,
    AuthResult,
    HeaderFinding,
    PhishingFinding,
    Severity,
    URLFinding,
    Verdict,
)
from email_security_analyzer.scoring import compute_risk_score


def test_clean_email_scores_zero_and_delivers():
    risk = compute_risk_score([], [], [], [], [])
    assert risk.total == 0
    assert risk.verdict == Verdict.DELIVER


def test_high_severity_signals_trigger_reject():
    header_findings = [
        HeaderFinding("from_reply_to_mismatch", False, Severity.HIGH, "mismatch", weight=15)
    ]
    auth_results = [
        AuthResult("spf", "fail", weight=15),
        AuthResult("dkim", "fail", weight=15),
        AuthResult("dmarc", "fail", weight=20),
    ]
    attachments = [
        AttachmentInfo(
            filename="invoice.pdf.exe", content_type="application/octet-stream",
            size_bytes=10, md5="x", sha256="y", extension=".exe",
            dangerous_extension=True, double_extension=True, weight=50,
        )
    ]
    risk = compute_risk_score(header_findings, auth_results, attachments, [], [])
    assert risk.total == 100  # capped
    assert risk.verdict == Verdict.REJECT


def test_moderate_signals_trigger_quarantine():
    url_findings = [URLFinding(url="http://bit.ly/x", domain="bit.ly", weight=10)]
    phishing_findings = [
        PhishingFinding("urgency_language", "urgent", Severity.MEDIUM, weight=20)
    ]
    auth_results = [AuthResult("spf", "fail", weight=15)]
    risk = compute_risk_score([], auth_results, [], url_findings, phishing_findings)
    assert 40 <= risk.total < 70
    assert risk.verdict == Verdict.QUARANTINE


def test_score_never_exceeds_100():
    attachments = [
        AttachmentInfo(
            filename="a.exe", content_type="x", size_bytes=1, md5="x", sha256="y",
            extension=".exe", dangerous_extension=True, weight=200,
        )
    ]
    risk = compute_risk_score([], [], attachments, [], [])
    assert risk.total == 100
