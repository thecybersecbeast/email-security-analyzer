# Contributing

Thanks for considering a contribution to Email Security Analyzer.

## Setup

```bash
git clone https://github.com/thecybersecbeast/email-security-analyzer.git
cd email-security-analyzer
pip install -e ".[dev,dns,whois,imap]"
pre-commit install   # optional, but runs the same checks CI does
```

## Before opening a PR

```bash
ruff check src tests      # lint
mypy src                  # type-check
pytest                    # tests + coverage
```

All three run in CI (`.github/workflows/ci.yml`) across Python 3.10–3.12,
plus `pip-audit` against `requirements.lock`. A PR won't merge if any of
them fail.

If you change `pyproject.toml`'s dependencies, regenerate the lockfile:

```bash
pip install pip-tools
pip-compile pyproject.toml --extra dev --extra dns --extra whois --extra imap \
  --generate-hashes -o requirements.lock
```

## Adding a new detection module

The pipeline is `analyzer.py` orchestrating five independent detectors
(`headers.py`, `auth.py`, `attachments.py`, `urls.py`, `phishing.py`) plus
the optional `reputation.py` domain-age check, all feeding into
`scoring.py`. To add a new signal:

1. Add a dataclass for its findings in `models.py` (follow the existing
   `HeaderFinding`/`URLFinding`/`PhishingFinding` pattern — a `weight: int`
   field is what `scoring.py` sums).
2. Write the detector as a pure function: `Message`/`str` in, a list of
   findings out. No side effects, no I/O beyond what's strictly necessary
   (see `reputation.py` for how an optional, network-touching detector
   degrades gracefully instead of raising).
3. Wire it into `EmailAnalyzer._analyze_message` in `analyzer.py` and into
   `compute_risk_score` in `scoring.py`.
4. Add it to `report.py`'s `to_text()` and `AnalysisResult.as_dict()` in
   `models.py` so it shows up in both output formats.
5. Add unit tests for the detector in isolation (see `tests/test_headers.py`
   for the pattern) and, if it affects the end-to-end score, extend
   `tests/test_analyzer_end_to_end.py`.

## Coding conventions

- Type hints everywhere; `mypy` runs in strict-ish mode via `pyproject.toml`.
- Prefer small, pure functions over stateful classes where reasonable.
- Library code logs through `logging`, never `print()` — `print()` is
  reserved for the CLI's actual report output (`cli.py`'s `_report()`).
- New CLI arguments get an explicit validator in `validation.py` rather
  than an inline `if` in `cli.py`.

## Reporting a security issue

This project analyzes untrusted email content and attachments by design.
If you find a way to make it do something it shouldn't (e.g. code
execution while parsing a malicious `.eml`), please open a private
security advisory on GitHub rather than a public issue.
