# Email Security Analyzer

A detection engine for suspicious, fraudulent, and malicious emails —
inspired by the same layered approach real secure-email gateways use.

It parses `.eml` messages and evaluates them across five detection
categories, combining every signal into a single weighted **risk score**
and a **deliver / quarantine / reject** verdict.

```
Internet
   │
   ▼
Mail Server (.eml)
   │
   ▼
EmailAnalyzer
   │
 ┌─┼──────────┬──────────┬───────────┐
 ▼ ▼          ▼          ▼           ▼
Headers   SPF/DKIM/DMARC  Attachments  URLs + Phishing content
   │
   ▼
Risk Score (0-100)
   │
   ▼
Deliver / Quarantine / Reject
```

## Detection categories

| Module          | What it checks |
|------------------|-----------------|
| `headers.py`     | From/Reply-To/Return-Path mismatches, brand-impersonating display names, missing/forged Received chain, Message-ID sanity, Date sanity |
| `auth.py`        | SPF / DKIM / DMARC results (parsed from `Authentication-Results`, with an optional live SPF DNS lookup) |
| `attachments.py` | SHA-256/MD5 hashing, dangerous extensions (`.exe`, `.js`, `.lnk`, ...), double-extension tricks (`invoice.pdf.exe`), embedded VBA macro detection in Office files |
| `urls.py`        | IP-literal URLs, punycode/homograph domains, URL shorteners, `@`-redirection tricks, and fuzzy brand typosquat detection (`micr0soft-support-login.com`) |
| `phishing.py`    | Urgency language, credential-harvesting phrasing, generic mass-mail greetings |

All findings feed into `scoring.py`, which sums weighted points per
category (capped at 100) and maps the total to a verdict:

| Score      | Verdict     |
|------------|-------------|
| 0–39       | Deliver     |
| 40–69      | Quarantine  |
| 70–100     | Reject      |

Thresholds and weights are constants at the top of `scoring.py` — tune
them to your own risk appetite.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/email-security-analyzer.git
cd email-security-analyzer
pip install -e ".[dev]"
```

Optional: install the `dns` extra to enable a supplementary live SPF
lookup (`pip install -e ".[dns]"`), used only as a fallback when a
message has no `Authentication-Results` header.

## Usage

### CLI

```bash
# Analyze a single message
email-security-analyzer analyze path/to/message.eml

# Analyze every .eml file in a directory
email-security-analyzer analyze ./samples/

# Machine-readable JSON output
email-security-analyzer analyze message.eml --json

# Use as a CI/CD gate: exit 1 if any sample is scored REJECT
email-security-analyzer analyze ./samples/ --fail-on-reject
```

### Library

```python
from email_security_analyzer import EmailAnalyzer
from email_security_analyzer.report import to_text

analyzer = EmailAnalyzer()
result = analyzer.analyze_file("message.eml")

print(result.risk.verdict, result.risk.total)
print(to_text(result))
```

## Example output

```
============================================================
EMAIL SECURITY ANALYSIS REPORT
============================================================
Subject   : URGENT: Verify your account within 24 hours
From      : PayPal Support <support@paypa1-secure-verify.com>
Reply-To  : recover@totally-not-a-scam.ru

-- Header Analysis --
  [FLAG (+15)] from_reply_to_mismatch: From domain does not match Reply-To domain...
  [FLAG (+20)] display_name_impersonation: Display name references 'paypal' but ...

-- Authentication (SPF / DKIM / DMARC) --
  [SPF=fail] Reported by receiving MTA: spf=fail
  [DKIM=fail] Reported by receiving MTA: dkim=fail
  [DMARC=fail] Reported by receiving MTA: dmarc=fail

-- Attachments --
  invoice.pdf.exe (55 bytes, sha256=e90f9df1d948c274...)
      ! Extension '.exe' is a common malware delivery format.
      ! Filename uses a double extension ...

-- Risk Score --
  headers              +60
  authentication       +50
  attachments          +75
  phishing_content     +40
  TOTAL                100/100

VERDICT: REJECT
============================================================
```

## Development

```bash
pip install -e ".[dev]"
ruff check src tests      # lint
mypy src                  # type-check
pytest                    # tests + coverage
```

Pinned versions for `dev`+`dns` extras live in `requirements.lock`
(regenerate with `pip-compile pyproject.toml --extra dev --extra dns -o
requirements.lock` after bumping a dependency). Dependabot opens weekly PRs
for both pip and GitHub Actions updates.

Test fixtures live in `tests/fixtures/` and include a clean email, a
phishing email (failed auth, typosquatted URL, disguised executable
attachment, urgency/credential-harvesting language), and a macro-laced
Office document — all synthetic, containing no real malware.

## CI/CD

`.github/workflows/ci.yml` runs on every push and PR:
lint (ruff) → type-check (mypy) → test with coverage (pytest, Python
3.10–3.12) → build sdist/wheel artifacts.

## Design notes & limitations

- **SPF/DKIM/DMARC**: trusts the `Authentication-Results` header stamped
  by the receiving MTA, since that reflects verification against the
  true connecting IP — something that can't be reconstructed reliably
  after the fact. The optional live SPF check is a simplified
  supplementary signal, not a full RFC 7208 implementation.
- **Macro detection**: structural (looks for an embedded `vbaProject.bin`
  inside the Office ZIP container), not full VBA static/behavioral
  analysis.
- **No sandboxing/AV/YARA integration**: this project focuses on
  fast, dependency-light static and heuristic analysis. It's designed
  to be extended — plug in a sandbox detonation service, hash lookups
  against a threat-intel feed, or a WHOIS/domain-age API as an
  additional weighted signal in `scoring.py`.
- **Brand/typosquat lists** in `headers.py` and `urls.py` are small
  starter sets — swap in your organization's real brand list for
  production use.

## License

MIT — see [LICENSE](LICENSE).
