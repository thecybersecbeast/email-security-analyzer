"""Command-line interface: `email-security-analyzer analyze <file-or-dir>`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import EmailAnalyzer
from .realtime.folder_watcher import watch_maildir
from .realtime.imap_watcher import watch_imap_idle, watch_imap_polling
from .report import to_json, to_text


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
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_p = subparsers.add_parser("analyze", help="Analyze one .eml file or a directory of .eml files")
    analyze_p.add_argument("path", type=Path, help="Path to a .eml file or a directory containing .eml files")
    analyze_p.add_argument("--json", action="store_true", help="Output JSON instead of a text report")
    analyze_p.add_argument(
        "--check-domain-age",
        action="store_true",
        help="Perform a live WHOIS lookup on the sender domain and factor "
             "registration age into the risk score (requires network + "
             "the 'whois' extra: pip install -e '.[whois]').",
    )
    analyze_p.add_argument(
        "--fail-on-reject",
        action="store_true",
        help="Exit with a non-zero status code if any analyzed email is scored REJECT "
             "(useful as a CI/CD gate on sample corpora).",
    )

    watch_p = subparsers.add_parser(
        "watch",
        help="Continuously monitor for new mail and analyze it in real time",
    )
    watch_p.add_argument("--json", action="store_true", help="Print each result as JSON")
    watch_p.add_argument(
        "--check-domain-age",
        action="store_true",
        help="Also factor sender domain age into scoring (requires network + the 'whois' extra).",
    )

    source_group = watch_p.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--maildir",
        type=Path,
        help="Path to a Maildir 'new' directory to watch for incoming .eml files. "
             "Processed messages are moved into sibling cur/quarantine/rejected directories.",
    )
    source_group.add_argument(
        "--imap-host",
        type=str,
        help="IMAP server hostname to watch (e.g. imap.gmail.com).",
    )

    watch_p.add_argument("--imap-user", help="IMAP username (required with --imap-host).")
    watch_p.add_argument(
        "--imap-password-env",
        default="EMAIL_ANALYZER_IMAP_PASSWORD",
        help="Name of the environment variable holding the IMAP password. "
             "Never pass passwords directly on the command line. "
             "(default: EMAIL_ANALYZER_IMAP_PASSWORD)",
    )
    watch_p.add_argument("--imap-mailbox", default="INBOX", help="Mailbox/folder to watch (default: INBOX).")
    watch_p.add_argument("--imap-port", type=int, default=None)
    watch_p.add_argument("--no-ssl", action="store_true", help="Disable TLS (not recommended).")
    watch_p.add_argument(
        "--poll-interval", type=float, default=10.0,
        help="Seconds between IMAP checks in polling mode (default: 10). Ignored with --idle.",
    )
    watch_p.add_argument(
        "--idle",
        action="store_true",
        help="Use true IMAP IDLE push notifications instead of polling "
             "(requires: pip install -e '.[imap]').",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        analyzer = EmailAnalyzer(check_domain_age=args.check_domain_age)
        if not args.path.exists():
            print(f"error: path not found: {args.path}", file=sys.stderr)
            return 2

        any_rejected = False
        for eml_path in _iter_eml_paths(args.path):
            result = analyzer.analyze_file(eml_path)
            if result.risk.verdict.value == "reject":
                any_rejected = True
            if args.path.is_dir():
                print(f"### {eml_path} ###")
            if args.json:
                print(to_json(result))
            else:
                print(to_text(result))
            print()

        if args.fail_on_reject and any_rejected:
            return 1
        return 0

    if args.command == "watch":
        import os

        analyzer = EmailAnalyzer(check_domain_age=args.check_domain_age)

        def _print_result(_source, result) -> None:
            print(to_json(result) if args.json else to_text(result))
            print(flush=True)

        try:
            if args.maildir:
                print(f"Watching {args.maildir} for new mail (Ctrl+C to stop)...")
                for source, result in watch_maildir(args.maildir, analyzer=analyzer):
                    _print_result(source, result)
                return 0

            if not args.imap_user:
                print("error: --imap-user is required with --imap-host", file=sys.stderr)
                return 2

            password = os.environ.get(args.imap_password_env)
            if not password:
                print(
                    f"error: environment variable {args.imap_password_env} is not set. "
                    f"Export your IMAP password there before running --imap-host.",
                    file=sys.stderr,
                )
                return 2

            common_kwargs = dict(
                host=args.imap_host,
                username=args.imap_user,
                password=password,
                mailbox=args.imap_mailbox,
                use_ssl=not args.no_ssl,
                port=args.imap_port,
                analyzer=analyzer,
            )

            mode = "IDLE (push)" if args.idle else f"polling every {args.poll_interval}s"
            print(f"Watching {args.imap_host}/{args.imap_mailbox} for new mail via {mode} "
                  f"(Ctrl+C to stop)...")

            if args.idle:
                watcher = watch_imap_idle(**common_kwargs)
            else:
                watcher = watch_imap_polling(poll_interval=args.poll_interval, **common_kwargs)

            for source, result in watcher:
                _print_result(source, result)
            return 0

        except KeyboardInterrupt:
            print("\nStopped.")
            return 0
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
