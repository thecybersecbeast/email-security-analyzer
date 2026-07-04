from email_security_analyzer import EmailAnalyzer, Verdict


def test_clean_email_is_delivered(fixtures_dir):
    result = EmailAnalyzer().analyze_file(fixtures_dir / "clean_email.eml")
    assert result.risk.verdict == Verdict.DELIVER
    assert result.risk.total < 40
    assert result.attachments == []


def test_phishing_email_is_rejected(fixtures_dir):
    result = EmailAnalyzer().analyze_file(fixtures_dir / "phishing_email.eml")

    # SPF/DKIM/DMARC all failed
    auth_by_mechanism = {a.mechanism: a for a in result.auth_results}
    assert auth_by_mechanism["spf"].result == "fail"
    assert auth_by_mechanism["dkim"].result == "fail"
    assert auth_by_mechanism["dmarc"].result == "fail"

    # From vs Reply-To mismatch flagged
    mismatch = next(f for f in result.header_findings if f.check == "from_reply_to_mismatch")
    assert mismatch.passed is False

    # Dangerous double-extension attachment flagged
    assert len(result.attachments) == 1
    attachment = result.attachments[0]
    assert attachment.dangerous_extension is True
    assert attachment.double_extension is True

    # Typosquatted URL flagged
    assert len(result.urls) == 1
    assert result.urls[0].weight > 0

    # Urgency + credential harvesting language flagged
    categories = {p.category for p in result.phishing_findings}
    assert "urgency_language" in categories
    assert "credential_harvesting" in categories

    # High combined score -> reject
    assert result.risk.total >= 70
    assert result.risk.verdict == Verdict.REJECT


def test_macro_attachment_is_flagged(fixtures_dir):
    result = EmailAnalyzer().analyze_file(fixtures_dir / "macro_email.eml")
    assert len(result.attachments) == 1
    assert result.attachments[0].macro_suspected is True
    assert result.attachments[0].weight >= 30
