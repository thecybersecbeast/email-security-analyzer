"""
Real-time IMAP mailbox watcher.

Two modes:

- ``watch_imap_polling`` — stdlib-only (``imaplib``), checks for new mail
  every ``poll_interval`` seconds. No extra dependency, works everywhere.
- ``watch_imap_idle`` — genuine push-based real-time notification using
  IMAP IDLE (RFC 2177) via the optional ``imapclient`` package. The
  connection blocks until the server *tells* it new mail arrived, so
  there is no polling delay at all.

Both act on the verdict: QUARANTINE and REJECT messages are copied into
a same-named mailbox folder and removed from the watched mailbox;
DELIVER messages are left untouched.
"""

from __future__ import annotations

import imaplib
import logging
import time
from collections.abc import Callable, Iterator

from ..analyzer import EmailAnalyzer
from ..models import AnalysisResult, Verdict

logger = logging.getLogger(__name__)

_ACTION_FOLDERS = {Verdict.QUARANTINE: "Quarantine", Verdict.REJECT: "Rejected"}


def _apply_imap_action(conn: imaplib.IMAP4, uid: bytes, verdict: Verdict) -> None:
    folder = _ACTION_FOLDERS.get(verdict)
    if folder is None:
        return
    uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
    conn.create(folder)  # no-op (returns NO) if it already exists; ignored
    status, _ = conn.uid("COPY", uid_str, folder)
    if status == "OK":
        conn.uid("STORE", uid_str, "+FLAGS", "(\\Deleted)")
        conn.expunge()


def watch_imap_polling(
    host: str,
    username: str,
    password: str,
    mailbox: str = "INBOX",
    poll_interval: float = 10.0,
    use_ssl: bool = True,
    port: int | None = None,
    analyzer: EmailAnalyzer | None = None,
    on_result: Callable[[bytes, AnalysisResult], None] | None = None,
    stop_after: int | None = None,
) -> Iterator[tuple[bytes, AnalysisResult]]:
    """Poll an IMAP mailbox for UNSEEN messages every ``poll_interval``
    seconds, analyze each, and act on the verdict. Yields ``(uid, result)``.

    Requires no optional dependency — ``imaplib`` is in the stdlib.
    """
    analyzer = analyzer or EmailAnalyzer()
    conn_cls = imaplib.IMAP4_SSL if use_ssl else imaplib.IMAP4
    conn = conn_cls(host, port) if port else conn_cls(host)
    conn.login(username, password)
    conn.select(mailbox)
    logger.info("Polling IMAP mailbox %r on %s every %.1fs", mailbox, host, poll_interval)

    processed = 0
    try:
        while stop_after is None or processed < stop_after:
            status, data = conn.uid("SEARCH", None, "UNSEEN")  # type: ignore[arg-type]  # charset=None is valid at runtime
            if status == "OK" and data and data[0]:
                for uid in data[0].split():
                    status, msg_data = conn.uid("FETCH", uid.decode(), "(RFC822)")
                    if status != "OK" or not msg_data or msg_data[0] is None:
                        continue
                    raw = msg_data[0][1]

                    try:
                        result = analyzer.analyze_bytes(raw)
                    except Exception:  # noqa: BLE001
                        logger.exception("Failed to analyze uid=%r; skipping.", uid)
                        continue

                    _apply_imap_action(conn, uid, result.risk.verdict)
                    logger.info(
                        "uid=%r verdict=%s score=%d",
                        uid, result.risk.verdict.value, result.risk.total,
                    )

                    if on_result:
                        on_result(uid, result)
                    yield uid, result

                    processed += 1
                    if stop_after is not None and processed >= stop_after:
                        return

            time.sleep(poll_interval)
    finally:
        try:
            conn.logout()
        except Exception:
            logger.debug("IMAP logout failed during cleanup; ignoring.", exc_info=True)


def watch_imap_idle(
    host: str,
    username: str,
    password: str,
    mailbox: str = "INBOX",
    use_ssl: bool = True,
    port: int | None = None,
    idle_timeout: int = 29 * 60,  # RFC 2177 recommends refreshing before 30 min
    analyzer: EmailAnalyzer | None = None,
    on_result: Callable[[int, AnalysisResult], None] | None = None,
    stop_after: int | None = None,
) -> Iterator[tuple[int, AnalysisResult]]:
    """True push-based real-time watcher using IMAP IDLE (RFC 2177).

    The connection blocks (no CPU spinning, no delay) until the server
    pushes a notification that new mail arrived, then analyzes it
    immediately.

    Requires the optional dependency: ``pip install -e ".[imap]"``
    """
    try:
        from imapclient import IMAPClient
    except ImportError as exc:
        raise RuntimeError(
            "IMAP IDLE requires the optional 'imapclient' package. "
            "Install it with: pip install -e '.[imap]' "
            "(or use polling mode instead, which needs no extra dependency)."
        ) from exc

    analyzer = analyzer or EmailAnalyzer()
    client = IMAPClient(host, port=port, ssl=use_ssl)
    client.login(username, password)
    client.select_folder(mailbox)
    logger.info("Watching IMAP mailbox %r on %s via IDLE (push, no polling delay)", mailbox, host)

    processed = 0
    try:
        while stop_after is None or processed < stop_after:
            client.idle()
            try:
                responses = client.idle_check(timeout=idle_timeout)
            finally:
                client.idle_done()

            if not responses:
                continue  # idle timed out with no events; just re-enter IDLE

            uids = client.search("UNSEEN")
            for uid in uids:
                raw = client.fetch([uid], ["RFC822"])[uid][b"RFC822"]

                try:
                    result = analyzer.analyze_bytes(raw)
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to analyze uid=%s; skipping.", uid)
                    continue

                folder = _ACTION_FOLDERS.get(result.risk.verdict)
                if folder is not None:
                    if folder not in client.list_folders():
                        client.create_folder(folder)
                    client.copy([uid], folder)
                    client.delete_messages([uid])

                logger.info(
                    "uid=%s verdict=%s score=%d",
                    uid, result.risk.verdict.value, result.risk.total,
                )

                if on_result:
                    on_result(uid, result)
                yield uid, result

                processed += 1
                if stop_after is not None and processed >= stop_after:
                    return
    finally:
        try:
            client.logout()
        except Exception:
            logger.debug("IMAP logout failed during cleanup; ignoring.", exc_info=True)
