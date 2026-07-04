"""
Email Security Analyzer
========================

A detection engine that inspects .eml email messages and evaluates
header integrity, SPF/DKIM/DMARC authentication, attachments, URLs,
and phishing indicators, producing a weighted risk score and a
deliver / quarantine / reject verdict.
"""

from .models import (
    AnalysisResult,
    AttachmentInfo,
    AuthResult,
    HeaderFinding,
    PhishingFinding,
    RiskScore,
    URLFinding,
    Verdict,
)
from .analyzer import EmailAnalyzer
from .reputation import DomainAgeResult, check_domain_age

__version__ = "0.1.0"

__all__ = [
    "EmailAnalyzer",
    "AnalysisResult",
    "AttachmentInfo",
    "AuthResult",
    "DomainAgeResult",
    "HeaderFinding",
    "PhishingFinding",
    "RiskScore",
    "URLFinding",
    "Verdict",
    "check_domain_age",
]
