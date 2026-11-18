"""Risk scoring.

* **Compliance score** (0-100): how much of the baseline the account meets. Each check
  contributes its severity weight, scaled by the share of its resources that pass, so a
  CRITICAL check counts ten times as much as a LOW one. Scoring per check rather than per
  resource stops a check with thousands of resources (snapshots, security groups) from
  drowning out a single failing root-account control.
* **Risk score**: the raw sum of severity weights of every failure. Unbounded, useful
  for trending an environment over time.
* **Grade**: letter grade from the compliance score, capped at C when any CRITICAL
  failure exists (one open RDP port to the world shouldn't hide behind a 95%).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .models import Finding, Severity, Status

GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


@dataclass
class Score:
    compliance: float
    risk: int
    grade: str
    total: int
    passed: int
    failed: int
    errors: int
    failures_by_severity: dict[str, int] = field(default_factory=dict)
    failures_by_service: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def grade_for(compliance: float, has_critical: bool) -> str:
    grade = next(letter for floor, letter in GRADE_BANDS if compliance >= floor)
    if has_critical and grade in {"A", "B"}:
        grade = "C"
    return grade


def compliance_percent(evaluated: list[Finding]) -> float:
    by_check: dict[str, list[Finding]] = defaultdict(list)
    for f in evaluated:
        by_check[f.check_id].append(f)
    possible = achieved = 0.0
    for group in by_check.values():
        weight = max(f.severity.weight for f in group)
        passed = sum(1 for f in group if not f.failed)
        possible += weight
        achieved += weight * passed / len(group)
    return 100.0 if possible == 0 else round(100.0 * achieved / possible, 1)


def score(findings: list[Finding]) -> Score:
    evaluated = [f for f in findings if f.status in (Status.PASS, Status.FAIL)]
    failures = [f for f in evaluated if f.failed]
    compliance = compliance_percent(evaluated)
    by_sev = Counter(f.severity.value for f in failures)
    return Score(
        compliance=compliance,
        risk=sum(f.severity.weight for f in failures),
        grade=grade_for(compliance, by_sev.get(Severity.CRITICAL.value, 0) > 0),
        total=len(findings),
        passed=len(evaluated) - len(failures),
        failed=len(failures),
        errors=sum(1 for f in findings if f.status is Status.ERROR),
        failures_by_severity={s.value: by_sev.get(s.value, 0) for s in Severity if s is not Severity.INFO},
        failures_by_service=dict(sorted(Counter(f.service for f in failures).items())),
    )
