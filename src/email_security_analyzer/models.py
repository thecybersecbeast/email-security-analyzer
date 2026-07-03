"""Data models shared across the analysis engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    DELIVER = "deliver"
    QUARANTINE = "quarantine"
    REJECT = "reject"


@dataclass
class HeaderFinding:
    check: str
    passed: bool
    severity: Severity
    detail: str
    weight: int = 0


@dataclass
class AuthResult:
    """Result of SPF / DKIM / DMARC evaluation."""

    mechanism: str  # "spf" | "dkim" | "dmarc"
    result: str  # "pass" | "fail" | "softfail" | "neutral" | "none" | "unknown"
    detail: str = ""
    weight: int = 0

    @property
    def failed(self) -> bool:
        return self.result in {"fail", "softfail"}


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha256: str
    extension: str
    double_extension: bool = False
    dangerous_extension: bool = False
    macro_suspected: bool = False
    findings: list[str] = field(default_factory=list)
    weight: int = 0


@dataclass
class URLFinding:
    url: str
    domain: str
    reasons: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    weight: int = 0


@dataclass
class PhishingFinding:
    category: str
    detail: str
    severity: Severity = Severity.INFO
    weight: int = 0


@dataclass
class RiskScore:
    total: int
    verdict: Verdict
    breakdown: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "verdict": self.verdict.value,
            "breakdown": self.breakdown,
        }


@dataclass
class AnalysisResult:
    subject: str
    sender: str
    reply_to: str | None
    header_findings: list[HeaderFinding]
    auth_results: list[AuthResult]
    attachments: list[AttachmentInfo]
    urls: list[URLFinding]
    phishing_findings: list[PhishingFinding]
    risk: RiskScore

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "sender": self.sender,
            "reply_to": self.reply_to,
            "header_findings": [vars(h) | {"severity": h.severity.value} for h in self.header_findings],
            "auth_results": [vars(a) for a in self.auth_results],
            "attachments": [vars(a) for a in self.attachments],
            "urls": [vars(u) | {"severity": u.severity.value} for u in self.urls],
            "phishing_findings": [vars(p) | {"severity": p.severity.value} for p in self.phishing_findings],
            "risk": self.risk.as_dict(),
        }
