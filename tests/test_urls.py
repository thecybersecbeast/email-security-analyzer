from email_security_analyzer.urls import analyze_url, extract_urls


def test_extract_urls_finds_all_links():
    body = "Visit https://example.com/a and also http://example.org/b?x=1 today."
    urls = extract_urls(body)
    assert urls == ["https://example.com/a", "http://example.org/b?x=1"]


def test_ip_based_url_flagged():
    finding = analyze_url("http://192.168.1.5/login")
    assert finding.weight > 0
    assert any("IP address" in r for r in finding.reasons)


def test_typosquatted_domain_flagged():
    finding = analyze_url("https://micr0soft.com/login")
    assert finding.weight > 0
    assert any("resembles" in r for r in finding.reasons)


def test_legitimate_domain_not_flagged():
    finding = analyze_url("https://microsoft.com/login")
    assert finding.weight == 0


def test_url_shortener_flagged():
    finding = analyze_url("https://bit.ly/abc123")
    assert any("shortener" in r for r in finding.reasons)


def test_punycode_domain_flagged():
    finding = analyze_url("https://xn--pypal-4ve.com/login")
    assert any("punycode" in r for r in finding.reasons)


def test_suspicious_tld_flagged():
    finding = analyze_url("https://free-gift-cards.top/claim")
    assert finding.weight > 0
    assert any(".top" in r for r in finding.reasons)


def test_common_tld_not_flagged_for_tld_alone():
    finding = analyze_url("https://example.com/newsletter")
    assert not any("Top-level domain" in r for r in finding.reasons)
