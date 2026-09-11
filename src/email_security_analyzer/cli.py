"""Command-line interface: `email-security-analyzer analyze|watch ...`."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .analyzer import EmailAnalyzer
from .report import to_json, to_text
from .validation import (
    ValidationError,
    validate_imap_host,
    validate_imap_password,
    validate_imap_port,
    validate_imap_user,
    validate_mailbox_name,
    validate_maildir_path,
    validate_poll_interval,
    validate_target_path,
    validate_watch_source,
)

logger = logging.getLogger(__name__)


def _configure_logging(verbose: bool) -> None:
    """Route library/watcher diagnostics through stdlib logging (to
    stderr), separate from the report output on stdout."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def _iter_eml_paths(target: Path):
    if target.is_dir():
        yield from sorted(target.rglob("*.eml"))
    else:
        yield target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-security-analyzer",
        description="Detection engine for suspicious/phishing/malicious emails.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug-level logging (applies to both subcommands).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- analyze ------------------------------------------------------
    analyze_p = subparsers.add_parser("analyze", help="Analyze one .eml file or a directory of .eml files")
    analyze_p.add_argument("path", type=Path, help="Path to a .eml file or a directory containing .eml files")
    analyze_p.add_argument("--json", action="store_true", help="Output JSON instead of a text report")
    analyze_p.add_argument(
        "--check-domain-age",
        action="store_true",
        help="Also factor in the sender domain's WHOIS registration age "
             "(requires network access and the optional 'whois' extra; "
             "degrades gracefully to no-op if either is unavailable).",
    )
    analyze_p.add_argument(
        "--fail-on-reject",
        action="store_true",
        help="Exit with a non-zero status code if any analyzed email is scored REJECT "
             "(useful as a CI/CD gate on sample corpora).",
    )

    # --- watch ----------------------------------------------------------
    watch_p = subparsers.add_parser(
        "watch",
        help="Continuously monitor a Maildir folder or an IMAP mailbox and analyze new mail as it arrives",
    )
    watch_p.add_argument("--maildir", type=Path, help="Path to a Maildir 'new/' directory to watch")
    watch_p.add_argument("--imap-host", help="IMAP server hostname, e.g. imap.gmail.com")
    watch_p.add_argument("--imap-user", help="IMAP username / email address")
    watch_p.add_argument("--imap-mailbox", default="INBOX", help="IMAP mailbox to watch (default: INBOX)")
    watch_p.add_argument(
        "--imap-password-env", default="EMAIL_ANALYZER_IMAP_PASSWORD",
        help="Name of the environment variable holding the IMAP password "
             "(default: EMAIL_ANALYZER_IMAP_PASSWORD). Never pass a password on the command line.",
    )
    watch_p.add_argument(
        "--imap-port", type=int, default=None, help="Override the default IMAP port",
    )
    watch_p.add_argument(
        "--no-ssl", action="store_true",
        help="Disable SSL for the IMAP connection (not recommended).",
    )
    watch_p.add_argument(
        "--idle", action="store_true",
        help="Use IMAP IDLE for push-based, zero-delay notification instead of polling "
             "(requires: pip install -e '.[imap]'). Ignored for --maildir.",
    )
    watch_p.add_argument(
        "--poll-interval", type=float, default=10.0,
        help="Seconds between polls in IMAP polling mode (default: 10). Maildir mode always polls every 1s.",
    )
    watch_p.add_argument(
        "--json", action="store_true",
        help="Emit each result as JSON instead of a text report.",
    )

    return parser


def _report(result, as_json: bool) -> None:
    print(to_json(result) if as_json else to_text(result))
    print()


def _run_analyze(args: argparse.Namespace) -> int:
    validate_target_path(args.path)
    analyzer = EmailAnalyzer(check_domain_age=args.check_domain_age)

    any_rejected = False
    for eml_path in _iter_eml_paths(args.path):
        result = analyzer.analyze_file(eml_path)
        if result.risk.verdict.value == "reject":
            any_rejected = True
        if args.path.is_dir():
            print(f"### {eml_path} ###")
        _report(result, args.json)

    if args.fail_on_reject and any_rejected:
        return 1
    return 0


def _run_watch(args: argparse.Namespace) -> int:
    validate_watch_source(args.maildir, args.imap_host)

    analyzer = EmailAnalyzer()

    if args.maildir is not None:
        from .realtime.folder_watcher import watch_maildir

        validate_maildir_path(args.maildir)
        for _path, result in watch_maildir(args.maildir, analyzer=analyzer):
            _report(result, args.json)
        return 0

    # IMAP mode
    host = validate_imap_host(args.imap_host)
    user = validate_imap_user(args.imap_user)
    mailbox = validate_mailbox_name(args.imap_mailbox)
    port = validate_imap_port(args.imap_port)
    password = validate_imap_password(os.environ.get(args.imap_password_env), args.imap_password_env)

    if args.idle:
        from .realtime.imap_watcher import watch_imap_idle

        for _, result in watch_imap_idle(
            host, user, password, mailbox=mailbox, use_ssl=not args.no_ssl, port=port, analyzer=analyzer
        ):
            _report(result, args.json)
    else:
        from .realtime.imap_watcher import watch_imap_polling

        poll_interval = validate_poll_interval(args.poll_interval)
        for _, result in watch_imap_polling(
            host, user, password, mailbox=mailbox, poll_interval=poll_interval,
            use_ssl=not args.no_ssl, port=port, analyzer=analyzer,
        ):
            _report(result, args.json)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    try:
        if args.command == "analyze":
            return _run_analyze(args)
        if args.command == "watch":
            try:
                return _run_watch(args)
            except KeyboardInterrupt:
                logger.info("Stopped watching (Ctrl+C).")
                return 0
        return 0
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
