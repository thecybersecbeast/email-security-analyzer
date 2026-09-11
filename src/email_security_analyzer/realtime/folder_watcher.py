"""
Real-time folder watcher for Maildir-style mail queues.

Watches a directory (e.g. ``Maildir/new/``) for newly-arrived ``.eml``
files, analyzes each the moment it appears, and files it into ``cur/``,
``quarantine/``, or ``rejected/`` based on the verdict — mirroring how a
real mail transfer agent milter acts on a message before final delivery.

Implemented with plain polling using only the standard library (no
'watchdog' dependency), so it works anywhere Python runs. A 1-second
poll interval is effectively real-time for email: a single mailbox does
not receive messages fast enough for that latency to matter, and it
avoids the platform-specific quirks of OS-level filesystem-event APIs.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from pathlib import Path

from ..analyzer import EmailAnalyzer
from ..models import AnalysisResult
from .actions import apply_maildir_action

logger = logging.getLogger(__name__)


def watch_maildir(
    maildir_new: str | Path,
    analyzer: EmailAnalyzer | None = None,
    poll_interval: float = 1.0,
    on_result: Callable[[Path, AnalysisResult], None] | None = None,
    stop_after: int | None = None,
) -> Iterator[tuple[Path, AnalysisResult]]:
    """Continuously watch ``maildir_new`` for new ``.eml`` files.

    Yields ``(original_path, AnalysisResult)`` for each message processed,
    and moves each file into a sibling ``cur/``, ``quarantine/``, or
    ``rejected/`` directory (next to ``new/``) based on its verdict.

    Parameters
    ----------
    stop_after:
        Process at most N messages then return. ``None`` runs forever
        (until interrupted). Mainly useful for tests and scripted runs.
    """
    analyzer = analyzer or EmailAnalyzer()
    maildir_new = Path(maildir_new)
    maildir_new.mkdir(parents=True, exist_ok=True)
    base_dir = maildir_new.parent
    logger.info("Watching Maildir folder %s (polling every %.1fs)", maildir_new, poll_interval)

    processed = 0
    seen: set[str] = set()

    while stop_after is None or processed < stop_after:
        for eml_path in sorted(maildir_new.glob("*.eml")):
            if eml_path.name in seen or not eml_path.exists():
                continue
            seen.add(eml_path.name)

            try:
                result = analyzer.analyze_file(eml_path)
            except Exception:  # noqa: BLE001 - one bad file must never kill the watcher
                logger.exception("Failed to analyze %s; skipping.", eml_path)
                continue

            apply_maildir_action(eml_path, result.risk.verdict.value, base_dir)
            logger.info(
                "%s verdict=%s score=%d",
                eml_path.name, result.risk.verdict.value, result.risk.total,
            )

            if on_result:
                on_result(eml_path, result)
            yield eml_path, result

            processed += 1
            if stop_after is not None and processed >= stop_after:
                return

        time.sleep(poll_interval)
