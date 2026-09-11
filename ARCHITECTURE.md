# Architecture

**Project type:** Python library and CLI. This is **not** an infrastructure
project — there is no Terraform, Helm, Pulumi, Ansible, or other
infrastructure-as-code here, and no plans to add any. Automated tooling that
classifies this repo should treat it as `python-library` / `cli`, not
`infra`.

## Layout

```
src/email_security_analyzer/
├── parser.py       # .eml -> email.message.Message
├── addressing.py   # shared From/Reply-To/Return-Path -> domain extraction
├── headers.py      # From/Reply-To mismatch, display-name impersonation, Received chain
├── auth.py         # SPF / DKIM / DMARC evaluation
├── attachments.py  # hashing, dangerous extensions, macro detection
├── urls.py         # IP-literal / punycode / shortener / typosquat / abused-TLD detection
├── phishing.py     # urgency, credential-harvesting, and financial-lure heuristics
├── reputation.py   # optional WHOIS-based sender domain-age check
├── validation.py   # explicit validation for CLI arguments
├── realtime/       # `watch` subcommand: Maildir + IMAP (polling and IDLE) monitors
├── scoring.py      # combines all signals into a weighted risk score + verdict
├── report.py       # text/JSON rendering of an analysis result
├── models.py       # typed dataclasses/enums shared across modules
└── cli.py          # `email-security-analyzer` entry point (`analyze`, `watch`)
```

Each detection module is independent and returns typed results
(`models.py`); `scoring.py` is the only place that combines them, so new
signals can be added without touching unrelated modules.

## Docker

A `Dockerfile` and `docker-compose.yml` are provided as a convenience way
to run the CLI without a local Python environment — this is still not
infrastructure-as-code (no Terraform/Helm/Pulumi/Ansible), just a
packaging aid for a single-container CLI tool. See the README's "Docker"
section for usage.
