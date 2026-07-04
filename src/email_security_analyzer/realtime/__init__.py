"""Real-time monitoring: watch a Maildir folder or an IMAP mailbox and
analyze each message the moment it arrives."""

from .folder_watcher import watch_maildir
from .imap_watcher import watch_imap_idle, watch_imap_polling

__all__ = ["watch_maildir", "watch_imap_idle", "watch_imap_polling"]
