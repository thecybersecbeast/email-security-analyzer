"""Explicit validation for values coming from the CLI entry points
(``analyze`` and ``watch``).

argparse already enforces types (``type=Path``, ``type=float``, ...), but
it doesn't enforce domain rules like "this directory must actually exist"
or "poll interval must be positive". Centralizing those checks here, with
one exception type, keeps ``cli.py`` free of scattered ad-hoc ``if``
statements and gives every entry point the same validation contract.
"""

from __future__ import annotations

from pathlib import Path


class ValidationError(ValueError):
    """Raised when a CLI argument fails validation. ``cli.py`` catches
    this at the top level and turns it into a clean stderr message plus
    a non-zero exit code, instead of a raw traceback."""


def validate_target_path(path: Path) -> Path:
    """A path given to `analyze` must exist (file or directory)."""
    if not path.exists():
        raise ValidationError(f"path not found: {path}")
    return path


def validate_maildir_path(path: Path) -> Path:
    """A Maildir target may not exist yet (the watcher creates it), but it
    must not already exist as a non-directory (e.g. a regular file)."""
    if path.exists() and not path.is_dir():
        raise ValidationError(f"--maildir must be a directory, not a file: {path}")
    return path


def validate_poll_interval(value: float) -> float:
    if value <= 0:
        raise ValidationError(f"--poll-interval must be a positive number of seconds, got {value}")
    return value


def validate_imap_host(host: str | None) -> str:
    if not host or not host.strip():
        raise ValidationError("--imap-host is required for IMAP watch mode")
    return host.strip()


def validate_imap_user(user: str | None) -> str:
    if not user or not user.strip():
        raise ValidationError("--imap-user is required for IMAP watch mode")
    return user.strip()


def validate_mailbox_name(mailbox: str) -> str:
    if not mailbox or not mailbox.strip():
        raise ValidationError("--imap-mailbox must not be empty")
    return mailbox.strip()


def validate_imap_port(port: int | None) -> int | None:
    if port is not None and not (0 < port <= 65535):
        raise ValidationError(f"--imap-port must be between 1 and 65535, got {port}")
    return port


def validate_watch_source(maildir: Path | None, imap_host: str | None) -> None:
    """Exactly one watch source must be selected."""
    if maildir is None and imap_host is None:
        raise ValidationError("watch requires either --maildir or --imap-host")
    if maildir is not None and imap_host is not None:
        raise ValidationError("watch accepts either --maildir or --imap-host, not both")


def validate_imap_password(password: str | None, password_env: str) -> str:
    if not password:
        raise ValidationError(
            f"IMAP password not found in environment variable '{password_env}'. "
            f"Set it before running watch, e.g.: export {password_env}=\"your-app-password\""
        )
    return password
