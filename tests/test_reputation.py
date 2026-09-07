import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from email_security_analyzer.reputation import check_domain_age


class _FakeWhoisRecord:
    def __init__(self, creation_date):
        self.creation_date = creation_date


@pytest.fixture
def fake_whois_module(monkeypatch):
    """Install a fake 'whois' module into sys.modules so tests never touch
    the network or real WHOIS servers."""
    fake_module = types.ModuleType("whois")
    fake_module._next_result = None

    def _whois(domain):
        result = fake_module._next_result
        if isinstance(result, Exception):
            raise result
        return result

    fake_module.whois = _whois
    monkeypatch.setitem(sys.modules, "whois", fake_module)
    return fake_module


def test_newly_registered_domain_flagged_critical(fake_whois_module):
    fake_whois_module._next_result = _FakeWhoisRecord(
        datetime.now(timezone.utc) - timedelta(hours=2)
    )
    result = check_domain_age("totally-not-a-scam.ru")
    assert result.result == "checked"
    assert result.age_days == 0
    assert result.weight == 30


def test_month_old_domain_flagged_lightly(fake_whois_module):
    fake_whois_module._next_result = _FakeWhoisRecord(
        datetime.now(timezone.utc) - timedelta(days=15)
    )
    result = check_domain_age("somewhat-new.com")
    assert result.weight == 10


def test_old_established_domain_not_flagged(fake_whois_module):
    fake_whois_module._next_result = _FakeWhoisRecord(
        datetime.now(timezone.utc) - timedelta(days=3650)
    )
    result = check_domain_age("microsoft.com")
    assert result.weight == 0


def test_whois_lookup_failure_degrades_to_unknown(fake_whois_module):
    fake_whois_module._next_result = RuntimeError("no such domain")
    result = check_domain_age("doesnotexist.invalid")
    assert result.result == "unknown"
    assert result.weight == 0


def test_missing_whois_dependency_degrades_to_unknown(monkeypatch):
    monkeypatch.setitem(sys.modules, "whois", None)
    # Simulate ImportError by removing any cached module and blocking import
    import builtins
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "whois":
            raise ImportError("no module named whois")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    result = check_domain_age("example.com")
    assert result.result == "unknown"
    assert result.weight == 0


def test_empty_domain_returns_unknown():
    result = check_domain_age("")
    assert result.result == "unknown"
    assert result.weight == 0
