from email_security_analyzer.phishing import analyze_phishing_content


def test_urgency_language_detected():
    findings = analyze_phishing_content(
        "Act now!", "Your account will be closed unless you act immediately."
    )
    categories = {f.category for f in findings}
    assert "urgency_language" in categories


def test_credential_harvesting_detected():
    findings = analyze_phishing_content(
        "Account update", "Please click here to login and confirm your password."
    )
    categories = {f.category for f in findings}
    assert "credential_harvesting" in categories


def test_benign_email_has_no_findings():
    findings = analyze_phishing_content(
        "Lunch tomorrow?", "Hey, are you free for lunch tomorrow at noon?"
    )
    assert findings == []


def test_financial_lure_detected():
    findings = analyze_phishing_content(
        "Congratulations!", "You've won a prize. Please purchase gift cards to claim your reward."
    )
    categories = {f.category for f in findings}
    assert "financial_lure" in categories


def test_financial_lure_not_triggered_by_unrelated_text():
    findings = analyze_phishing_content(
        "Team lunch", "Free coffee in the break room today, no strings attached."
    )
    categories = {f.category for f in findings}
    assert "financial_lure" not in categories
