"""Command-line entry point: ``aws-audit``."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from . import __version__
from .checks import all_checks
from .clients import ClientFactory
from .models import Severity
from .report import FORMATS, write_reports
from .scanner import run_audit, select_checks

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

COLORS = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[34m", "INFO": "\033[37m"}
RESET = "\033[0m"


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-audit",
        description="Audit an AWS account against a security baseline and generate a compliance report. "
        "Uses read-only API calls only.",
    )
    p.add_argument("--profile", help="AWS named profile to use")
    p.add_argument("--regions", type=_csv, help="comma-separated regions (default: all enabled regions)")
    p.add_argument("--home-region", default="us-east-1", help="region for global services (default: us-east-1)")
    p.add_argument("--services", type=_csv, help="only run checks for these services, e.g. s3,iam")
    p.add_argument("--checks", type=_csv, help="only run these check IDs, e.g. S3-001,EC2-003")
    p.add_argument("--exclude", type=_csv, default=[], help="check IDs to skip")
    p.add_argument(
        "--format", type=_csv, default=["md", "html"], help=f"report formats: {','.join(FORMATS)} (default: md,html)"
    )
    p.add_argument("--output-dir", type=Path, default=Path("reports"), help="where to write reports")
    p.add_argument("--min-severity", default="info", help="hide failures below this severity")
    p.add_argument(
        "--fail-on",
        default=None,
        help="exit with code 1 if any failure at or above this severity exists (for CI gating)",
    )
    p.add_argument("--workers", type=int, default=16, help="concurrent API workers (default: 16)")
    p.add_argument("--list-checks", action="store_true", help="print the baseline and exit")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def list_checks() -> None:
    for cls in all_checks():
        m = cls.meta
        scope = "global" if m.global_service else "regional"
        print(f"{m.id:<8} {m.severity.value:<9} {m.service:<11} {scope:<9} {m.title}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    if args.list_checks:
        list_checks()
        return EXIT_OK

    try:
        min_sev = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on) if args.fail_on else None
        bad = [f for f in args.format if f not in FORMATS]
        if bad:
            raise ValueError(f"unknown format(s): {', '.join(bad)}")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    checks = select_checks(args.services, args.checks, args.exclude)
    if not checks:
        print("error: no checks selected", file=sys.stderr)
        return EXIT_ERROR

    try:
        clients = ClientFactory(boto3.session.Session(profile_name=args.profile))
        result = run_audit(
            clients,
            regions=args.regions,
            checks=checks,
            home_region=args.home_region,
            max_workers=args.workers,
            min_severity=min_sev,
        )
    except NoCredentialsError:
        print("error: no AWS credentials found (set AWS_PROFILE or run `aws configure`)", file=sys.stderr)
        return EXIT_ERROR
    except (ClientError, BotoCoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    color = sys.stdout.isatty() and not args.no_color
    print_summary(result, color)
    for path in write_reports(result, args.output_dir, args.format):
        print(f"Report written: {path}")

    if fail_on and any(f.severity.rank >= fail_on.rank for f in result.failures):
        return EXIT_FINDINGS
    return EXIT_OK


def print_summary(result, color: bool) -> None:
    s = result.score

    def c(sev: str, text: str) -> str:
        return f"{COLORS[sev]}{text}{RESET}" if color else text

    print(f"\nAccount {result.account_id} · {len(result.regions)} region(s) · {len(result.checks_run)} checks")
    print(f"Grade {s.grade} · compliance {s.compliance}% · risk score {s.risk}")
    print(f"{s.passed} passed, {s.failed} failed, {s.errors} not evaluated\n")
    for f in result.failures[:25]:
        sev = c(f.severity.value, f"{f.severity.value:<8}")
        print(f"  {sev} {f.check_id:<8} {f.region:<14} {f.resource_id}: {f.message}")
    if len(result.failures) > 25:
        print(f"  ... and {len(result.failures) - 25} more (see the report)")
    print()


if __name__ == "__main__":
    sys.exit(main())
