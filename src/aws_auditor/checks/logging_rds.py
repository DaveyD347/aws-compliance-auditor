"""CloudTrail and RDS checks."""

from __future__ import annotations

from collections.abc import Iterable

from ..models import CheckMeta, Finding, Severity
from .base import Check, paginate, register


@register
class CloudTrailMultiRegion(Check):
    meta = CheckMeta(
        id="CT-001",
        title="A multi-region CloudTrail trail is logging",
        service="cloudtrail",
        severity=Severity.HIGH,
        description="Without an active multi-region trail, API activity in unused regions goes unrecorded.",
        remediation="aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> "
        "--is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name org-trail",
        references=("CIS AWS Foundations 3.1",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        ct = self.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        logging = []
        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging"):
                logging.append(trail["Name"])
        if logging:
            yield self.passed("cloudtrail", f"Multi-region trail(s) logging: {', '.join(sorted(set(logging)))}")
        else:
            yield self.failed("cloudtrail", "No multi-region trail is actively logging")


@register
class CloudTrailLogValidation(Check):
    meta = CheckMeta(
        id="CT-002",
        title="CloudTrail log file validation is enabled",
        service="cloudtrail",
        severity=Severity.LOW,
        description="Log file validation lets you prove trail logs were not tampered with after delivery.",
        remediation="aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
        references=("CIS AWS Foundations 3.2",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        trails = self.client("cloudtrail").describe_trails(includeShadowTrails=False).get("trailList", [])
        for trail in trails:
            if trail.get("LogFileValidationEnabled"):
                yield self.passed(trail["Name"], "Log file validation enabled")
            else:
                yield self.failed(trail["Name"], "Log file validation disabled")


@register
class RdsPublicAccess(Check):
    meta = CheckMeta(
        id="RDS-001",
        title="RDS instances are not publicly accessible",
        service="rds",
        severity=Severity.HIGH,
        description="A publicly accessible DB instance gets a public DNS name and IP reachable from the internet.",
        remediation="aws rds modify-db-instance --db-instance-identifier <id> "
        "--no-publicly-accessible --apply-immediately",
        references=("CIS AWS Foundations 2.3.3",),
    )

    def evaluate(self) -> Iterable[Finding]:
        for db in paginate(self.client("rds"), "describe_db_instances", "DBInstances"):
            if db.get("PubliclyAccessible"):
                yield self.failed(
                    db["DBInstanceIdentifier"], "Instance is publicly accessible", engine=db.get("Engine")
                )
            else:
                yield self.passed(db["DBInstanceIdentifier"], "Instance is private", engine=db.get("Engine"))


@register
class RdsEncryption(Check):
    meta = CheckMeta(
        id="RDS-002",
        title="RDS instance storage is encrypted",
        service="rds",
        severity=Severity.HIGH,
        description="Unencrypted RDS storage, automated backups and snapshots hold data in plaintext.",
        remediation="Encryption can't be enabled in place: snapshot the instance, copy the snapshot with a KMS key, "
        "and restore a new instance from the encrypted copy.",
        references=("CIS AWS Foundations 2.3.1",),
    )

    def evaluate(self) -> Iterable[Finding]:
        for db in paginate(self.client("rds"), "describe_db_instances", "DBInstances"):
            if db.get("StorageEncrypted"):
                yield self.passed(db["DBInstanceIdentifier"], "Storage is encrypted")
            else:
                yield self.failed(db["DBInstanceIdentifier"], "Storage is NOT encrypted")
