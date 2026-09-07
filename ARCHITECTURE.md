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
├── headers.py      # From/Reply-To/Return-Path, display-name impersonation, Received chain
├── auth.py         # SPF / DKIM / DMARC evaluation
├── attachments.py  # hashing, dangerous extensions, macro detection
├── urls.py         # IP-literal / punycode / shortener / typosquat detection
├── phishing.py     # urgency + credential-harvesting language heuristics
├── scoring.py      # combines all signals into a weighted risk score + verdict
├── report.py       # text/JSON rendering of an analysis result
├── models.py       # typed dataclasses/enums shared across modules
└── cli.py          # `email-security-analyzer` entry point
```

Each detection module is independent and returns typed results
(`models.py`); `scoring.py` is the only place that combines them, so new
signals can be added without touching unrelated modules.

## Why no Docker/IaC

This is a pip-installable library and CLI meant to be run directly or
imported into a larger pipeline (e.g. a mail-processing service), not a
deployable service on its own — so there is intentionally no Dockerfile,
Kubernetes manifest, or infrastructure code in this repository.
