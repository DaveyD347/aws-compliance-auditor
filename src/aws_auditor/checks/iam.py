"""IAM checks: root account hygiene, MFA, key rotation, password policy, admin policies."""

from __future__ import annotations

import csv
import io
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from urllib.parse import unquote

from botocore.exceptions import ClientError

from ..models import CheckMeta, Finding, Severity
from .base import Check, error_code, paginate, register

KEY_MAX_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 14
MIN_PASSWORD_REUSE_PREVENTION = 24


def _parse_ts(value: str) -> datetime | None:
    if not value or value in {"N/A", "not_supported", "no_information"}:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def fetch_credential_report(iam, timeout: float = 60.0, poll: float = 2.0) -> list[dict]:
    """Generate (if needed) and download the IAM credential report as a list of rows."""
    deadline = time.monotonic() + timeout
    while True:
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        if time.monotonic() > deadline:
            raise TimeoutError("IAM credential report generation timed out")
        time.sleep(poll)
    content = iam.get_credential_report()["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


class IamCheck(Check):
    def credential_report(self) -> list[dict]:
        return self.clients.memo("iam:credential_report", lambda: fetch_credential_report(self.client("iam")))

    def account_summary(self) -> dict:
        return self.clients.memo("iam:account_summary", lambda: self.client("iam").get_account_summary()["SummaryMap"])


@register
class RootMfa(IamCheck):
    meta = CheckMeta(
        id="IAM-001",
        title="Root account has MFA enabled",
        service="iam",
        severity=Severity.CRITICAL,
        description="The root user has unrestricted access to the account and must be protected by MFA.",
        remediation="Sign in as root and enable a hardware or virtual MFA device under Security credentials.",
        references=("CIS AWS Foundations 1.5",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        if self.account_summary().get("AccountMFAEnabled", 0) == 1:
            yield self.passed("<root_account>", "Root MFA is enabled")
        else:
            yield self.failed("<root_account>", "Root MFA is NOT enabled")


@register
class RootAccessKeys(IamCheck):
    meta = CheckMeta(
        id="IAM-002",
        title="Root account has no access keys",
        service="iam",
        severity=Severity.CRITICAL,
        description="Long-lived root access keys cannot be scoped down and are a prime target for attackers.",
        remediation="Delete the root access keys and use IAM roles or Identity Center users instead.",
        references=("CIS AWS Foundations 1.4",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        if self.account_summary().get("AccountAccessKeysPresent", 0):
            yield self.failed("<root_account>", "Root access keys are present")
        else:
            yield self.passed("<root_account>", "No root access keys")


@register
class ConsoleUsersMfa(IamCheck):
    meta = CheckMeta(
        id="IAM-003",
        title="IAM users with console access have MFA",
        service="iam",
        severity=Severity.HIGH,
        description="Console passwords without MFA are vulnerable to phishing and credential stuffing.",
        remediation="Enforce MFA for the user, or remove the login profile if console access is not needed.",
        references=("CIS AWS Foundations 1.10",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        for row in self.credential_report():
            if row["user"] == "<root_account>" or row.get("password_enabled") != "true":
                continue
            if row.get("mfa_active") == "true":
                yield self.passed(row["user"], "Console user has MFA")
            else:
                yield self.failed(row["user"], "Console password enabled without MFA")


@register
class AccessKeyRotation(IamCheck):
    meta = CheckMeta(
        id="IAM-004",
        title=f"Active access keys are rotated within {KEY_MAX_AGE_DAYS} days",
        service="iam",
        severity=Severity.MEDIUM,
        description="Old access keys increase the blast radius of a leak; rotate or replace them with roles.",
        remediation="Create a new key, deploy it, then deactivate and delete the old one "
        "(aws iam update-access-key / delete-access-key).",
        references=("CIS AWS Foundations 1.14",),
        global_service=True,
    )

    now: datetime | None = None  # overridable in tests

    def evaluate(self) -> Iterable[Finding]:
        now = self.now or datetime.now(timezone.utc)
        for row in self.credential_report():
            if row["user"] == "<root_account>":
                continue
            for n in (1, 2):
                if row.get(f"access_key_{n}_active") != "true":
                    continue
                rotated = _parse_ts(row.get(f"access_key_{n}_last_rotated", ""))
                resource = f"{row['user']} (key {n})"
                if rotated is None:
                    continue
                age = (now - rotated).days
                if age > KEY_MAX_AGE_DAYS:
                    yield self.failed(resource, f"Access key is {age} days old", age_days=age)
                else:
                    yield self.passed(resource, f"Access key is {age} days old", age_days=age)


@register
class PasswordPolicy(IamCheck):
    meta = CheckMeta(
        id="IAM-005",
        title="Account password policy meets the baseline",
        service="iam",
        severity=Severity.MEDIUM,
        description=f"Require at least {MIN_PASSWORD_LENGTH} characters and prevent reuse of the last "
        f"{MIN_PASSWORD_REUSE_PREVENTION} passwords.",
        remediation=f"aws iam update-account-password-policy --minimum-password-length {MIN_PASSWORD_LENGTH} "
        f"--password-reuse-prevention {MIN_PASSWORD_REUSE_PREVENTION}",
        references=("CIS AWS Foundations 1.8", "CIS AWS Foundations 1.9"),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        try:
            policy = self.client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchEntity":
                yield self.failed("account-password-policy", "No password policy is set (AWS defaults apply)")
                return
            raise
        problems = []
        if policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
            problems.append(f"minimum length {policy.get('MinimumPasswordLength')} < {MIN_PASSWORD_LENGTH}")
        if policy.get("PasswordReusePrevention", 0) < MIN_PASSWORD_REUSE_PREVENTION:
            problems.append(
                f"reuse prevention {policy.get('PasswordReusePrevention', 0)} < {MIN_PASSWORD_REUSE_PREVENTION}"
            )
        if problems:
            yield self.failed("account-password-policy", "; ".join(problems), problems=problems)
        else:
            yield self.passed("account-password-policy", "Password policy meets the baseline")


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def grants_full_admin(document: dict) -> bool:
    """True if any Allow statement grants Action '*' on Resource '*'."""
    for stmt in _as_list(document.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        if "*" in _as_list(stmt.get("Action", [])) and "*" in _as_list(stmt.get("Resource", [])):
            return True
    return False


@register
class CustomerManagedAdminPolicies(IamCheck):
    meta = CheckMeta(
        id="IAM-006",
        title="No attached customer-managed policies grant full '*:*' admin",
        service="iam",
        severity=Severity.HIGH,
        description="Policies allowing Action '*' on Resource '*' violate least privilege.",
        remediation="Replace the policy with a scoped one, or use the AWS-managed AdministratorAccess "
        "policy only for a small, MFA-protected break-glass role.",
        references=("CIS AWS Foundations 1.16",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        iam = self.client("iam")
        for pol in paginate(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True):
            doc = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])["PolicyVersion"][
                "Document"
            ]
            if isinstance(doc, str):  # boto3 normally decodes this; be defensive
                import json

                doc = json.loads(unquote(doc))
            if grants_full_admin(doc):
                yield self.failed(
                    pol["PolicyName"],
                    f"Grants '*:*' and is attached to {pol.get('AttachmentCount', '?')} entities",
                    arn=pol["Arn"],
                )
            else:
                yield self.passed(pol["PolicyName"], "Policy is scoped", arn=pol["Arn"])
