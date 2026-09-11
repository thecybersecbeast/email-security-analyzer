"""Parse raw .eml content into a Python email.message.Message object."""

from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import cast


def parse_eml_bytes(data: bytes) -> EmailMessage:
    """Parse raw RFC 5322 message bytes into an email.message.EmailMessage."""
    return cast(EmailMessage, BytesParser(policy=policy.default).parsebytes(data))


def parse_eml_file(path: str | Path) -> EmailMessage:
    """Parse a .eml file from disk."""
    path = Path(path)
    with path.open("rb") as fh:
        return cast(EmailMessage, BytesParser(policy=policy.default).parse(fh))


def get_body_text(msg: EmailMessage) -> str:
    """Extract the best-effort plain text body (falls back to stripped HTML)."""
    if msg.is_multipart():
        # Prefer text/plain, fall back to text/html
        plain_parts = []
        html_parts = []
        for part in msg.walk():
            content_type = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            if content_type == "text/plain":
                plain_parts.append(_decode_part(part))
            elif content_type == "text/html":
                html_parts.append(_decode_part(part))
        if plain_parts:
            return "\n".join(plain_parts)
        if html_parts:
            return "\n".join(html_parts)
        return ""
    content_type = msg.get_content_type()
    if content_type in ("text/plain", "text/html"):
        return _decode_part(msg)
    return ""


def _decode_part(part: EmailMessage) -> str:
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            return content.decode(errors="replace")
        return str(content)
    except Exception:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode(errors="replace")
        if payload is None:
            return ""
        return str(payload)


def iter_attachments(msg: EmailMessage):
    """Yield (filename, content_type, raw_bytes) for every attachment/part with a filename."""
    if not msg.is_multipart():
        return
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        yield filename, part.get_content_type(), payload
