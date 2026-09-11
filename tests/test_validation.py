from pathlib import Path

import pytest

from email_security_analyzer.validation import (
    ValidationError,
    validate_imap_host,
    validate_imap_password,
    validate_imap_port,
    validate_imap_user,
    validate_mailbox_name,
    validate_maildir_path,
    validate_poll_interval,
    validate_target_path,
    validate_watch_source,
)


def test_validate_target_path_accepts_existing(tmp_path):
    f = tmp_path / "a.eml"
    f.write_text("x")
    assert validate_target_path(f) == f


def test_validate_target_path_rejects_missing(tmp_path):
    with pytest.raises(ValidationError, match="not found"):
        validate_target_path(tmp_path / "missing.eml")


def test_validate_maildir_path_rejects_file(tmp_path):
    f = tmp_path / "not_a_dir"
    f.write_text("x")
    with pytest.raises(ValidationError, match="must be a directory"):
        validate_maildir_path(f)


def test_validate_maildir_path_allows_nonexistent(tmp_path):
    target = tmp_path / "Maildir" / "new"
    assert validate_maildir_path(target) == target


@pytest.mark.parametrize("value", [0, -1, -10.5])
def test_validate_poll_interval_rejects_non_positive(value):
    with pytest.raises(ValidationError, match="positive"):
        validate_poll_interval(value)


def test_validate_poll_interval_accepts_positive():
    assert validate_poll_interval(5.0) == 5.0


@pytest.mark.parametrize("host", [None, "", "   "])
def test_validate_imap_host_rejects_empty(host):
    with pytest.raises(ValidationError, match="imap-host"):
        validate_imap_host(host)


def test_validate_imap_host_strips_and_accepts():
    assert validate_imap_host(" imap.gmail.com ") == "imap.gmail.com"


@pytest.mark.parametrize("user", [None, "", "  "])
def test_validate_imap_user_rejects_empty(user):
    with pytest.raises(ValidationError, match="imap-user"):
        validate_imap_user(user)


def test_validate_mailbox_name_rejects_empty():
    with pytest.raises(ValidationError, match="mailbox"):
        validate_mailbox_name("")


def test_validate_mailbox_name_accepts_value():
    assert validate_mailbox_name("INBOX") == "INBOX"


@pytest.mark.parametrize("port", [0, -1, 70000])
def test_validate_imap_port_rejects_out_of_range(port):
    with pytest.raises(ValidationError, match="1 and 65535"):
        validate_imap_port(port)


def test_validate_imap_port_accepts_none_and_valid():
    assert validate_imap_port(None) is None
    assert validate_imap_port(993) == 993


def test_validate_watch_source_requires_one():
    with pytest.raises(ValidationError, match="requires either"):
        validate_watch_source(None, None)


def test_validate_watch_source_rejects_both():
    with pytest.raises(ValidationError, match="not both"):
        validate_watch_source(Path("/tmp/x"), "imap.gmail.com")


def test_validate_watch_source_accepts_exactly_one():
    validate_watch_source(Path("/tmp/x"), None)
    validate_watch_source(None, "imap.gmail.com")


def test_validate_imap_password_rejects_missing():
    with pytest.raises(ValidationError, match="EMAIL_ANALYZER_IMAP_PASSWORD"):
        validate_imap_password(None, "EMAIL_ANALYZER_IMAP_PASSWORD")


def test_validate_imap_password_accepts_present():
    assert validate_imap_password("hunter2", "EMAIL_ANALYZER_IMAP_PASSWORD") == "hunter2"
