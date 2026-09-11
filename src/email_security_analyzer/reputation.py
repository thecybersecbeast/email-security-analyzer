"""
Domain reputation via registration age (WHOIS).

A domain registered hours or days before it starts sending email is one of
the strongest phishing indicators there is — attackers routinely burn
domains after a single campaign. This is intentionally optional: it
requires the 'whois' extra and network access, and gracefully degrades to
result="unknown" (zero weight) when either is unavailable, so the rest of
the pipeline never depends on it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import DomainAgeResult, severity_from_weight

# Weight tiers by domain age. Tune to taste.
_AGE_WEIGHTS = (
    (1, 30),      # < 1 day old
    (7, 20),      # < 7 days old
    (30, 10),     # < 30 days old
)


def check_domain_age(domain: str) -> DomainAgeResult:
    """Look up a domain's WHOIS creation date and score it by age.

    Requires the optional 'python-whois' dependency and network/WHOIS
    access. Returns result="unknown" (weight=0) if either is missing, a
    lookup fails, or the registrar doesn't expose a creation date —
    this signal should only ever add risk, never silently assume safety.
    """
    if not domain:
        return DomainAgeResult(domain=domain, age_days=None, result="unknown",
                                detail="No domain supplied.")

    try:
        import whois  # type: ignore
    except ImportError:
        return DomainAgeResult(
            domain=domain, age_days=None, result="unknown",
            detail="python-whois not installed; skipping domain-age check.",
        )

    try:
        record = whois.whois(domain)
        created = record.creation_date
    except Exception as exc:  # noqa: BLE001 - WHOIS failures vary widely by TLD/registrar
        return DomainAgeResult(
            domain=domain, age_days=None, result="unknown",
            detail=f"WHOIS lookup failed for {domain}: {exc}",
        )

    if isinstance(created, list):
        created = created[0] if created else None
    if created is None:
        return DomainAgeResult(
            domain=domain, age_days=None, result="unknown",
            detail=f"WHOIS record for {domain} has no creation date.",
        )
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - created).days

    weight = 0
    for threshold_days, tier_weight in _AGE_WEIGHTS:
        if age_days < threshold_days:
            weight = tier_weight
            break

    severity = severity_from_weight(weight, critical=30, high=20, medium=10)

    detail = f"Domain '{domain}' was registered {age_days} day(s) ago."
    if weight:
        detail += " Newly-registered domains are a strong phishing indicator."

    return DomainAgeResult(
        domain=domain, age_days=age_days, result="checked",
        detail=detail, severity=severity, weight=weight,
    )
