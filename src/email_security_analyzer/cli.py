"""Command-line interface: `email-security-analyzer analyze <file-or-dir>`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import EmailAnalyzer
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
        "--fail-on-reject",
        action="store_true",
        help="Exit with a non-zero status code if any analyzed email is scored REJECT "
             "(useful as a CI/CD gate on sample corpora).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        analyzer = EmailAnalyzer()
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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
