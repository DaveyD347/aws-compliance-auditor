"""Base class and registry for compliance checks.

Adding a rule is a matter of subclassing :class:`Check`, filling in ``meta`` and
implementing :meth:`Check.evaluate`. Decorate the class with :func:`register`
and it is picked up by the scanner automatically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..models import CheckMeta, Finding, Status

_REGISTRY: dict[str, type[Check]] = {}

# Error codes that mean "you are not allowed to look", as opposed to a real bug.
ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "OptInRequired",
}


def register(cls: type[Check]) -> type[Check]:
    if cls.meta.id in _REGISTRY:
        raise ValueError(f"duplicate check id {cls.meta.id}")
    _REGISTRY[cls.meta.id] = cls
    return cls


def all_checks() -> list[type[Check]]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


class Check(ABC):
    meta: CheckMeta

    def __init__(self, clients: Any, region: str) -> None:
        self.clients = clients
        self.region = region

    def client(self, service: str):
        return self.clients.get(service, self.region)

    # -- helpers for subclasses -------------------------------------------------

    def passed(self, resource_id: str, message: str, **details: Any) -> Finding:
        return self._finding(Status.PASS, resource_id, message, details)

    def failed(self, resource_id: str, message: str, **details: Any) -> Finding:
        return self._finding(Status.FAIL, resource_id, message, details)

    def _finding(self, status: Status, resource_id: str, message: str, details: dict) -> Finding:
        return Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            service=self.meta.service,
            severity=self.meta.severity,
            status=status,
            resource_id=resource_id,
            region="global" if self.meta.global_service else self.region,
            message=message,
            remediation=self.meta.remediation if status is Status.FAIL else "",
            details=details,
        )

    # -- execution ----------------------------------------------------------------

    @abstractmethod
    def evaluate(self) -> Iterable[Finding]:
        """Yield one finding per evaluated resource."""

    def run(self) -> list[Finding]:
        """Run the check, converting AWS errors into ERROR findings instead of crashing."""
        findings: list[Finding] = []
        try:
            for finding in self.evaluate():
                findings.append(finding)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            reason = "insufficient permissions" if code in ACCESS_DENIED_CODES else "AWS API error"
            findings.append(
                self._finding(Status.ERROR, "-", f"Check not evaluated ({reason}: {code})", {"error": str(exc)})
            )
        except BotoCoreError as exc:
            findings.append(self._finding(Status.ERROR, "-", f"Check not evaluated: {exc}", {}))
        return findings


def paginate(client, operation: str, result_key: str, **kwargs: Any) -> Iterator[Any]:
    """Iterate over every item of ``result_key`` across all pages of ``operation``."""
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")
