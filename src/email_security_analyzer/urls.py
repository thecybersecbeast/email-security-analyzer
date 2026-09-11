"""URL extraction from email bodies and heuristic risk analysis."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import URLFinding, severity_from_weight

URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

# A small reference set of frequently-impersonated brand domains for
# typosquatting comparison. Extend/replace with a real brand list in prod.
PROTECTED_BRAND_DOMAINS = [
    "microsoft.com", "paypal.com", "apple.com", "amazon.com", "google.com",
    "netflix.com", "bankofamerica.com", "wellsfargo.com", "chase.com",
    "docusign.com", "office.com", "outlook.com", "linkedin.com", "facebook.com",
]

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# TLDs with a track record of being disproportionately used in phishing and
# malware-delivery campaigns, generally because they are free, cheap, or
# loosely moderated. This is a supplementary signal, not a standalone
# verdict — plenty of legitimate sites use these too, so the weight is kept
# modest relative to stronger signals like typosquatting or IP-literal URLs.
# Source: recurring findings across public abuse-tracking reports (e.g.
# Spamhaus, Interisle) for .zip/.mov (Google's 2023 gTLD rollout was
# immediately abused for archive/video-lure phishing), classic free
# dynamic-DNS-style TLDs (.tk/.ml/.ga/.cf/.gq from Freenom), and a handful
# of cheap new gTLDs favored for disposable phishing domains.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "country", "stream", "gdn", "kim",
    "loan", "men", "date", "review", "party", "trade", "webcam",
}


def _tld(host: str) -> str:
    parts = host.rsplit(".", 1)
    return parts[-1] if len(parts) == 2 else ""


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def extract_urls(body_text: str) -> list[str]:
    return URL_RE.findall(body_text or "")


def _registrable_label(domain: str) -> str:
    """Return the second-level label, e.g. 'micr0soft-support-login' for
    'micr0soft-support-login.com', so we compare brand names against the
    part attackers actually control, not the whole padded domain."""
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


def _fuzzy_contains(haystack: str, needle: str, max_distance: int = 1) -> int | None:
    """Slide a window of ~len(needle) across haystack and return the best
    (smallest) Levenshtein distance found, or None if nothing is close.
    Catches brand names padded with extra words (micr0soft-support-login)
    as well as simple character-substitution typosquats (micr0soft)."""
    if len(needle) < 5:  # too short to fuzzy-match without false positives
        return None
    best: int | None = None
    for size in (len(needle) - 1, len(needle), len(needle) + 1):
        if size <= 0:
            continue
        for start in range(0, max(len(haystack) - size + 1, 1)):
            window = haystack[start:start + size]
            if not window:
                continue
            distance = _levenshtein(window, needle)
            if best is None or distance < best:
                best = distance
    return best


def _distance_budget(brand_name: str) -> int:
    """Shorter brand names (e.g. 'apple', 'chase') need an exact fuzzy match
    (budget 0) to avoid false positives on unrelated words that happen to
    share a few letters. Longer, more distinctive names (e.g. 'microsoft',
    'docusign') can tolerate a 1-2 character substitution/insertion."""
    length = len(brand_name)
    if length < 6:
        return 0
    if length < 11:
        return 1
    return 2


def _closest_brand_match(domain: str) -> tuple[str, int] | None:
    label = _registrable_label(domain)
    best: tuple[str, int] | None = None
    for brand_domain in PROTECTED_BRAND_DOMAINS:
        brand_name = brand_domain.split(".")[0]  # e.g. "microsoft"
        if domain == brand_domain or domain.endswith("." + brand_domain):
            continue  # legitimate domain or subdomain, not typosquatting
        budget = _distance_budget(brand_name)
        distance = _fuzzy_contains(label, brand_name, max_distance=budget)
        if distance is None or distance > budget:
            continue
        if best is None or distance < best[1]:
            best = (brand_domain, distance)
    return best


def analyze_url(url: str) -> URLFinding:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    finding = URLFinding(url=url, domain=host)
    reasons: list[str] = []
    weight = 0

    if IP_HOST_RE.match(host):
        reasons.append("URL uses a raw IP address instead of a domain name.")
        weight += 20

    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("Domain uses punycode encoding — possible homograph/IDN attack.")
        weight += 25

    if host in KNOWN_SHORTENERS:
        reasons.append(f"'{host}' is a URL shortener that hides the true destination.")
        weight += 10

    if "@" in url.split("//", 1)[-1].split("/")[0]:
        reasons.append("URL contains an '@' before the host — classic redirection trick.")
        weight += 20

    subdomain_count = host.count(".")
    if subdomain_count >= 4:
        reasons.append(f"Unusually deep subdomain chain ({host}).")
        weight += 10

    tld = _tld(host)
    if tld in SUSPICIOUS_TLDS:
        reasons.append(
            f"Top-level domain '.{tld}' is disproportionately used for "
            f"phishing/malware delivery — treat links here with extra scrutiny."
        )
        weight += 8

    match = _closest_brand_match(host)
    if match:
        brand, distance = match
        # distance 0 means the brand name is embedded verbatim in an
        # unrelated domain (e.g. "microsoft" inside "microsoft-support-login.ru");
        # small positive distance means a character-substitution typo
        # (e.g. "micr0soft"). Both are strong typosquatting signals.
        reasons.append(
            f"Domain '{host}' closely resembles brand '{brand}' "
            f"(fuzzy match distance {distance}) — possible typosquatting "
            f"or brand impersonation."
        )
        weight += 40

    finding.reasons = reasons
    finding.weight = weight
    finding.severity = severity_from_weight(weight, critical=40, high=20, medium=10)

    return finding


def analyze_urls(body_text: str) -> list[URLFinding]:
    return [analyze_url(url) for url in extract_urls(body_text)]
