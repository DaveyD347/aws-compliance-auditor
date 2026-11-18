"""Render an AuditResult as Markdown, HTML or JSON."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from jinja2 import Environment, PackageLoader

from .checks import all_checks
from .models import Severity
from .scanner import AuditResult

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
FORMATS = ("md", "html", "json")


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _check_summary(result: AuditResult) -> list[dict]:
    """One row per check: how many resources passed / failed / errored."""
    meta = {c.meta.id: c.meta for c in all_checks()}
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"PASS": 0, "FAIL": 0, "ERROR": 0})
    for f in result.findings:
        counts[f.check_id][f.status.value] += 1
    rows = []
    for cid in result.checks_run:
        c = counts[cid]
        status = "FAIL" if c["FAIL"] else ("ERROR" if c["ERROR"] and not c["PASS"] else "PASS")
        if not any(c.values()):
            status = "N/A"
        rows.append({"id": cid, "meta": meta[cid], "status": status, **c})
    return rows


def render_markdown(result: AuditResult) -> str:
    s = result.score
    out = [
        "# AWS Compliance Audit Report",
        "",
        f"**Account:** `{result.account_id}`  ",
        f"**Regions:** {', '.join(result.regions)}  ",
        f"**Generated:** {result.finished_at:%Y-%m-%d %H:%M:%S UTC}  ",
        f"**Duration:** {(result.finished_at - result.started_at).total_seconds():.1f}s",
        "",
        "## Summary",
        "",
        "| Grade | Compliance | Risk score | Passed | Failed | Errors |",
        "|:-:|:-:|:-:|:-:|:-:|:-:|",
        f"| **{s.grade}** | {s.compliance}% | {s.risk} | {s.passed} | {s.failed} | {s.errors} |",
        "",
        "| Severity | Failures |",
        "|---|--:|",
    ]
    out += [f"| {SEVERITY_EMOJI[sev]} {sev} | {n} |" for sev, n in s.failures_by_severity.items()]

    out += ["", "## Checks", "", "| ID | Check | Severity | Result | Pass | Fail |", "|---|---|---|:-:|--:|--:|"]
    icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️", "N/A": "➖"}
    for row in _check_summary(result):
        m = row["meta"]
        out.append(
            f"| {row['id']} | {_md_escape(m.title)} | {m.severity.value} | {icon[row['status']]} "
            f"| {row['PASS']} | {row['FAIL']} |"
        )

    out += ["", "## Failed findings", ""]
    if not result.failures:
        out.append("No failed findings. 🎉")
    else:
        out += ["| Severity | ID | Region | Resource | Issue |", "|---|---|---|---|---|"]
        for f in result.failures:
            out.append(
                f"| {SEVERITY_EMOJI[f.severity.value]} {f.severity.value} | {f.check_id} | {f.region} "
                f"| `{_md_escape(f.resource_id)}` | {_md_escape(f.message)} |"
            )
        out += ["", "## Remediation", ""]
        seen = set()
        for f in result.failures:
            if f.check_id in seen:
                continue
            seen.add(f.check_id)
            out += [f"### {f.check_id}: {f.title}", "", f.remediation, ""]

    if result.errors:
        out += ["", "## Checks that could not be evaluated", "", "| ID | Region | Reason |", "|---|---|---|"]
        out += [f"| {f.check_id} | {f.region} | {_md_escape(f.message)} |" for f in result.errors]
    return "\n".join(out).rstrip() + "\n"


def render_html(result: AuditResult) -> str:
    # Always escape: resource names, tags and SG names are attacker-controllable input.
    env = Environment(loader=PackageLoader("aws_auditor", "templates"), autoescape=True)
    template = env.get_template("report.html.j2")
    remediations = {}
    for f in result.failures:
        remediations.setdefault(f.check_id, (f.title, f.remediation))
    return template.render(
        r=result,
        s=result.score,
        checks=_check_summary(result),
        remediations=remediations,
        severities=[sev.value for sev in Severity if sev is not Severity.INFO],
        duration=(result.finished_at - result.started_at).total_seconds(),
    )


def render_json(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)


RENDERERS = {"md": render_markdown, "html": render_html, "json": render_json}


def write_reports(result: AuditResult, output_dir: Path, formats: list[str], stem: str | None = None) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = stem or f"compliance-report-{result.account_id}-{result.finished_at:%Y%m%dT%H%M%SZ}"
    written = []
    for fmt in formats:
        path = output_dir / f"{stem}.{fmt}"
        path.write_text(RENDERERS[fmt](result), encoding="utf-8")
        written.append(path)
    return written
