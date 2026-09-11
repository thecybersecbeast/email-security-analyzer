import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from email_security_analyzer import EmailAnalyzer
from email_security_analyzer.report import to_text


class _FakeWhoisRecord:
    def __init__(self, creation_date):
        self.creation_date = creation_date


@pytest.fixture
def fake_whois_module(monkeypatch):
    """Same fake-whois pattern as test_reputation.py, reused here to prove
    the domain-age signal actually reaches the analyzer's risk score and
    report — not just that reputation.check_domain_age works in isolation."""
    fake_module = types.ModuleType("whois")
    fake_module._next_result = None

    def _whois(domain):
        return fake_module._next_result

    fake_module.whois = _whois
    monkeypatch.setitem(sys.modules, "whois", fake_module)
    return fake_module


def test_check_domain_age_adds_weight_to_risk_score(fixtures_dir, fake_whois_module):
    fake_whois_module._next_result = _FakeWhoisRecord(
        datetime.now(timezone.utc) - timedelta(hours=2)
    )
    baseline = EmailAnalyzer(check_domain_age=False).analyze_file(fixtures_dir / "clean_email.eml")
    with_age = EmailAnalyzer(check_domain_age=True).analyze_file(fixtures_dir / "clean_email.eml")

    assert with_age.domain_age is not None
    assert with_age.domain_age.result == "checked"
    assert with_age.risk.breakdown.get("domain_reputation") == 30
    assert with_age.risk.total > baseline.risk.total


def test_check_domain_age_appears_in_text_report(fixtures_dir, fake_whois_module):
    fake_whois_module._next_result = _FakeWhoisRecord(
        datetime.now(timezone.utc) - timedelta(hours=2)
    )
    result = EmailAnalyzer(check_domain_age=True).analyze_file(fixtures_dir / "clean_email.eml")
    text = to_text(result)
    assert "Domain Reputation" in text


def test_check_domain_age_false_by_default_leaves_domain_age_none(fixtures_dir):
    result = EmailAnalyzer().analyze_file(fixtures_dir / "clean_email.eml")
    assert result.domain_age is None
