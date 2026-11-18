"""Core data types shared by checks, the scoring engine and the reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Higher is more severe. Used for sorting and --fail-on thresholds."""
        return _SEVERITY_ORDER.index(self)

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.upper())
        except ValueError as exc:
            valid = ", ".join(s.value.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"  # the check could not be evaluated (e.g. AccessDenied)


@dataclass(frozen=True)
class CheckMeta:
    """Static metadata describing a rule in the baseline."""

    id: str
    title: str
    service: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...] = ()
    global_service: bool = False  # True for IAM/S3 etc.: run once, not per region


@dataclass
class Finding:
    check_id: str
    title: str
    service: str
    severity: Severity
    status: Status
    resource_id: str
    region: str
    message: str
    remediation: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.status is Status.FAIL

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data
