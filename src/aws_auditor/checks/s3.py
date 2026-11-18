"""S3 bucket checks: public exposure, encryption and versioning."""

from __future__ import annotations

import json
from collections.abc import Iterable
from functools import cached_property

from botocore.exceptions import ClientError

from ..models import CheckMeta, Finding, Severity
from .base import Check, error_code, paginate, register

PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}

BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


class S3Check(Check):
    """Shared plumbing: list buckets once and talk to each bucket in its home region."""

    @cached_property
    def buckets(self) -> list[dict]:
        return list(paginate(self.client("s3"), "list_buckets", "Buckets"))

    def bucket_client(self, bucket: dict):
        region = bucket.get("BucketRegion")
        if not region:
            loc = self.client("s3").get_bucket_location(Bucket=bucket["Name"])
            region = loc.get("LocationConstraint") or "us-east-1"
        return self.clients.get("s3", region)


@register
class S3PublicAccessBlock(S3Check):
    meta = CheckMeta(
        id="S3-001",
        title="S3 bucket Block Public Access is fully enabled",
        service="s3",
        severity=Severity.HIGH,
        description="All four S3 Block Public Access settings should be on for every bucket "
        "unless it intentionally serves public content.",
        remediation="aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        references=("CIS AWS Foundations 2.1.4",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        for bucket in self.buckets:
            name = bucket["Name"]
            try:
                cfg = self.bucket_client(bucket).get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            except ClientError as exc:
                if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    raise
                cfg = {}
            missing = [flag for flag in BPA_FLAGS if not cfg.get(flag)]
            if missing:
                yield self.failed(name, f"Block Public Access settings disabled: {', '.join(missing)}", missing=missing)
            else:
                yield self.passed(name, "All Block Public Access settings enabled")


@register
class S3PublicAcl(S3Check):
    meta = CheckMeta(
        id="S3-002",
        title="S3 bucket ACL does not grant public access",
        service="s3",
        severity=Severity.CRITICAL,
        description="Bucket ACLs granting AllUsers or AuthenticatedUsers expose data to the internet.",
        remediation="Remove the public grants (aws s3api put-bucket-acl --bucket <name> --acl private) "
        "and enable Object Ownership 'BucketOwnerEnforced' to disable ACLs entirely.",
        references=("CIS AWS Foundations 2.1.4",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        for bucket in self.buckets:
            name = bucket["Name"]
            acl = self.bucket_client(bucket).get_bucket_acl(Bucket=name)
            public = sorted(
                {
                    f"{PUBLIC_GRANTEES[g['Grantee']['URI']]}:{g['Permission']}"
                    for g in acl.get("Grants", [])
                    if g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES
                }
            )
            if public:
                yield self.failed(name, f"ACL grants public access ({', '.join(public)})", grants=public)
            else:
                yield self.passed(name, "No public ACL grants")


def _policy_public_statements(policy: dict) -> list[str]:
    """Return Sids (or indexes) of Allow statements open to everyone with no Condition."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    offenders = []
    for idx, stmt in enumerate(statements):
        if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
            continue
        principal = stmt.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        if principal == "*" or aws == "*" or (isinstance(aws, list) and "*" in aws):
            offenders.append(stmt.get("Sid") or f"#{idx}")
    return offenders


@register
class S3PublicPolicy(S3Check):
    meta = CheckMeta(
        id="S3-003",
        title="S3 bucket policy does not allow anonymous access",
        service="s3",
        severity=Severity.CRITICAL,
        description="A bucket policy with Principal '*' and no Condition grants access to anyone.",
        remediation="Restrict the Principal to specific accounts/roles or add a Condition "
        "(e.g. aws:SourceVpce, aws:PrincipalOrgID).",
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        for bucket in self.buckets:
            name = bucket["Name"]
            try:
                raw = self.bucket_client(bucket).get_bucket_policy(Bucket=name)["Policy"]
            except ClientError as exc:
                if error_code(exc) == "NoSuchBucketPolicy":
                    yield self.passed(name, "No bucket policy")
                    continue
                raise
            offenders = _policy_public_statements(json.loads(raw))
            if offenders:
                yield self.failed(
                    name, f"Policy statement(s) {', '.join(offenders)} allow Principal '*'", statements=offenders
                )
            else:
                yield self.passed(name, "Bucket policy does not allow anonymous access")


@register
class S3DefaultEncryption(S3Check):
    meta = CheckMeta(
        id="S3-004",
        title="S3 bucket has default encryption configured",
        service="s3",
        severity=Severity.MEDIUM,
        description="Default server-side encryption ensures new objects are encrypted at rest.",
        remediation="aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration "
        '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}\'',
        references=("CIS AWS Foundations 2.1.1",),
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        for bucket in self.buckets:
            name = bucket["Name"]
            try:
                rules = self.bucket_client(bucket).get_bucket_encryption(Bucket=name)[
                    "ServerSideEncryptionConfiguration"
                ]["Rules"]
            except ClientError as exc:
                if error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
                    yield self.failed(name, "No default encryption configured")
                    continue
                raise
            algos = sorted({r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "?") for r in rules})
            yield self.passed(name, f"Default encryption: {', '.join(algos)}", algorithms=algos)


@register
class S3Versioning(S3Check):
    meta = CheckMeta(
        id="S3-005",
        title="S3 bucket versioning is enabled",
        service="s3",
        severity=Severity.LOW,
        description="Versioning protects against accidental deletion and ransomware-style overwrites.",
        remediation="aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled",
        global_service=True,
    )

    def evaluate(self) -> Iterable[Finding]:
        for bucket in self.buckets:
            name = bucket["Name"]
            status = self.bucket_client(bucket).get_bucket_versioning(Bucket=name).get("Status", "Disabled")
            if status == "Enabled":
                yield self.passed(name, "Versioning enabled")
            else:
                yield self.failed(name, f"Versioning is {status}")
