"""Orchestrates checks across services and regions concurrently."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .checks import all_checks
from .checks.base import Check
from .clients import ClientFactory
from .models import Finding, Severity, Status
from .scoring import Score, score

log = logging.getLogger(__name__)


@dataclass
class AuditResult:
    account_id: str
    regions: list[str]
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    score: Score
    checks_run: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[Finding]:
        return sorted(
            (f for f in self.findings if f.failed),
            key=lambda f: (-f.severity.rank, f.check_id, f.region, f.resource_id),
        )

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.status is Status.ERROR]

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "regions": self.regions,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "checks_run": self.checks_run,
            "score": self.score.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }


def select_checks(
    services: Iterable[str] | None = None,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> list[type[Check]]:
    services = {s.lower() for s in services or []}
    include = {c.upper() for c in include or []}
    exclude = {c.upper() for c in exclude or []}
    selected = []
    for cls in all_checks():
        if services and cls.meta.service not in services:
            continue
        if include and cls.meta.id not in include:
            continue
        if cls.meta.id in exclude:
            continue
        selected.append(cls)
    return selected


def run_audit(
    clients: ClientFactory,
    regions: list[str] | None = None,
    checks: list[type[Check]] | None = None,
    home_region: str = "us-east-1",
    max_workers: int = 16,
    min_severity: Severity = Severity.INFO,
) -> AuditResult:
    started = datetime.now(timezone.utc)
    checks = checks if checks is not None else all_checks()
    regions = regions or clients.enabled_regions(home_region)
    account_id = clients.account_id()

    tasks: list[Check] = []
    for cls in checks:
        if cls.meta.global_service:
            tasks.append(cls(clients, home_region))
        else:
            tasks.extend(cls(clients, region) for region in regions)

    log.info("Running %d check tasks across %d region(s)", len(tasks), len(regions))
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(task.run): task for task in tasks}
        for fut in as_completed(futures):
            task = futures[fut]
            try:
                findings.extend(fut.result())
            except Exception as exc:  # a bug in a check must not sink the whole audit
                log.exception("Check %s failed in %s", task.meta.id, task.region)
                findings.append(
                    task._finding(Status.ERROR, "-", f"Unexpected error: {exc.__class__.__name__}: {exc}", {})
                )

    findings = [f for f in findings if f.status is not Status.FAIL or f.severity.rank >= min_severity.rank]
    findings.sort(key=lambda f: (f.check_id, f.region, f.resource_id))
    return AuditResult(
        account_id=account_id,
        regions=regions,
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        findings=findings,
        score=score(findings),
        checks_run=[c.meta.id for c in checks],
    )
