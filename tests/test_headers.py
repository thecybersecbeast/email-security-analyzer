from email.message import EmailMessage

from email_security_analyzer.headers import analyze_headers


def _msg(**headers) -> EmailMessage:
    msg = EmailMessage()
    for key, value in headers.items():
        msg[key.replace("_", "-")] = value
    msg.set_content("body")
    return msg


def test_reply_to_mismatch_flagged():
    msg = _msg(
        From="Someone <alice@example.com>",
        Reply_To="scammer@evil.com",
        Message_ID="<1@example.com>",
        Received="from x by y",
    )
    findings = analyze_headers(msg)
    mismatch = next(f for f in findings if f.check == "from_reply_to_mismatch")
    assert mismatch.passed is False
    assert mismatch.weight == 15


def test_matching_reply_to_passes():
    msg = _msg(
        From="Someone <alice@example.com>",
        Reply_To="alice@example.com",
        Message_ID="<1@example.com>",
        Received="from x by y",
    )
    findings = analyze_headers(msg)
    mismatch = next(f for f in findings if f.check == "from_reply_to_mismatch")
    assert mismatch.passed is True


def test_brand_impersonation_flagged():
    msg = _msg(
        From='"Microsoft Support" <no-reply@totally-unrelated.ru>',
        Message_ID="<1@totally-unrelated.ru>",
        Received="from x by y",
    )
    findings = analyze_headers(msg)
    impersonation = next(f for f in findings if f.check == "display_name_impersonation")
    assert impersonation.passed is False


def test_missing_received_chain_flagged():
    msg = _msg(From="alice@example.com", Message_ID="<1@example.com>")
    findings = analyze_headers(msg)
    received = next(f for f in findings if f.check == "received_chain")
    assert received.passed is False
