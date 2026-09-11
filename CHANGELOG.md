# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `watch` CLI subcommand, wiring the previously-undocumented-in-code
  Maildir and IMAP watchers (`watch_maildir`, `watch_imap_polling`,
  `watch_imap_idle`) into the actual command line: `--maildir`,
  `--imap-host`/`--imap-user`/`--imap-mailbox`/`--imap-port`, `--idle`,
  `--poll-interval`, `--json`.
- `--check-domain-age` now actually runs the WHOIS-based sender
  domain-age check (`reputation.py`) and folds it into the risk score
  and report/JSON output as a `domain_reputation` breakdown entry.
- `validation.py`: explicit validation for every CLI entry-point argument
  (paths, IMAP host/user/port/mailbox, poll interval, password env var),
  with a single `ValidationError` surfaced as a clean `error: ...` message
  instead of a raw traceback.
- `-v`/`--verbose` global flag; structured `logging` output (to stderr)
  replaces the `print()` calls previously used for watcher diagnostics.
- `CONTRIBUTING.md`, `.env.example`, `docker-compose.yml`, this changelog.

### Fixed
- `pyproject.toml` was missing the `whois` and `imap` optional-dependency
  groups entirely, even though the README documented
  `pip install -e ".[whois]"` / `".[imap]"` and `reputation.py`/
  `imap_watcher.py` depend on them. Both extras are now declared.
- `requirements.lock` now actually matches what's installable (previously
  covered only `dev`+`dns`; now covers `dev`+`dns`+`whois`+`imap` with
  pinned hashes).
- Two pre-existing `mypy` errors in `parser.py` and `realtime/imap_watcher.py`
  (untyped `email.message.EmailMessage` methods, `imaplib` stub mismatches).
- Placeholder `YOUR_USERNAME` URLs in `pyproject.toml` and the README/CI
  badge now point at the real repository.

### Changed
- Deduplicated repeated `Finding`-construction boilerplate: `headers.py`
  now uses a `_record()` helper for its pass/fail checks, and the
  weight → severity bucketing duplicated in `urls.py` and `reputation.py`
  is now a single `severity_from_weight()` in `models.py`.
- Domain-extraction logic (`From`/`Reply-To`/`Return-Path` → domain) moved
  out of `headers.py` into a shared `addressing.py` module.

## [0.1.0] - 2026-09-11

Initial public release: `.eml` analysis across headers, SPF/DKIM/DMARC,
attachments, URLs, and phishing-content heuristics, combined into a
weighted risk score and deliver/quarantine/reject verdict.
