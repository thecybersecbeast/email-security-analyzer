import json

import pytest

from email_security_analyzer.cli import build_parser, main


def test_analyze_clean_email_exits_zero(fixtures_dir, capsys):
    exit_code = main(["analyze", str(fixtures_dir / "clean_email.eml")])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "VERDICT: PASS (DELIVER)" in out


def test_analyze_json_output_is_valid_json(fixtures_dir, capsys):
    exit_code = main(["analyze", str(fixtures_dir / "clean_email.eml"), "--json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["risk"]["verdict"] == "deliver"


def test_analyze_fail_on_reject_returns_nonzero(fixtures_dir, capsys):
    exit_code = main(["analyze", str(fixtures_dir / "phishing_email.eml"), "--fail-on-reject"])
    assert exit_code == 1


def test_analyze_missing_path_is_a_clean_validation_error(tmp_path, capsys):
    exit_code = main(["analyze", str(tmp_path / "nope.eml")])
    assert exit_code == 2
    assert "error: path not found" in capsys.readouterr().err


def test_watch_requires_a_source(capsys):
    exit_code = main(["watch"])
    assert exit_code == 2
    assert "requires either --maildir or --imap-host" in capsys.readouterr().err


def test_watch_rejects_both_sources(tmp_path, capsys):
    exit_code = main(["watch", "--maildir", str(tmp_path), "--imap-host", "imap.gmail.com"])
    assert exit_code == 2
    assert "not both" in capsys.readouterr().err


def test_watch_imap_without_user_is_rejected(capsys):
    exit_code = main(["watch", "--imap-host", "imap.gmail.com"])
    assert exit_code == 2
    assert "imap-user" in capsys.readouterr().err


def test_watch_imap_without_password_env_is_rejected(monkeypatch, capsys):
    monkeypatch.delenv("EMAIL_ANALYZER_IMAP_PASSWORD", raising=False)
    exit_code = main(["watch", "--imap-host", "imap.gmail.com", "--imap-user", "me@gmail.com"])
    assert exit_code == 2
    assert "EMAIL_ANALYZER_IMAP_PASSWORD" in capsys.readouterr().err


def test_build_parser_exposes_watch_subcommand():
    """Regression guard: `watch` must actually be registered as a
    subcommand (previously documented in the README but not wired up)."""
    parser = build_parser()
    args = parser.parse_args(["watch", "--maildir", "/tmp/Maildir/new"])
    assert args.command == "watch"


def test_build_parser_exposes_check_domain_age_flag():
    parser = build_parser()
    args = parser.parse_args(["analyze", "some.eml", "--check-domain-age"])
    assert args.check_domain_age is True


def test_analyze_check_domain_age_flag_runs_end_to_end(fixtures_dir, capsys, monkeypatch):
    """--check-domain-age should run without error even with no network/whois
    available, degrading gracefully (result simply omits domain_age)."""
    exit_code = main(["analyze", str(fixtures_dir / "clean_email.eml"), "--check-domain-age", "--json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    # 'whois' extra isn't installed in the test env, so the lookup degrades
    # to a no-op and domain_age is simply absent rather than crashing.
    assert "risk" in payload


@pytest.mark.parametrize("bad_port", ["0", "70000"])
def test_watch_rejects_out_of_range_port(tmp_path, capsys, bad_port):
    exit_code = main([
        "watch", "--imap-host", "imap.gmail.com", "--imap-user", "me@gmail.com",
        "--imap-port", bad_port,
    ])
    assert exit_code == 2
    assert "65535" in capsys.readouterr().err
