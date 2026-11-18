"""EC2 / EBS / VPC checks: encryption at rest, network exposure, instance metadata."""

from __future__ import annotations

from collections.abc import Iterable

from ..models import CheckMeta, Finding, Severity
from .base import Check, paginate, register

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

# Ports that should never be reachable from the whole internet.
SENSITIVE_PORTS: dict[int, str] = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


@register
class EbsVolumeEncryption(Check):
    meta = CheckMeta(
        id="EC2-001",
        title="EBS volumes are encrypted",
        service="ec2",
        severity=Severity.HIGH,
        description="Unencrypted EBS volumes (and their snapshots) store data in plaintext at rest.",
        remediation="Snapshot the volume, copy the snapshot with --encrypted, create a new volume from it "
        "and swap it in. Enable EBS encryption by default to prevent recurrence.",
        references=("CIS AWS Foundations 2.2.1",),
    )

    def evaluate(self) -> Iterable[Finding]:
        for vol in paginate(self.client("ec2"), "describe_volumes", "Volumes"):
            attached = [a["InstanceId"] for a in vol.get("Attachments", [])]
            details = {"size_gib": vol.get("Size"), "attached_to": attached}
            if vol.get("Encrypted"):
                yield self.passed(vol["VolumeId"], "Volume is encrypted", **details)
            else:
                yield self.failed(vol["VolumeId"], "Volume is not encrypted", **details)


@register
class EbsEncryptionByDefault(Check):
    meta = CheckMeta(
        id="EC2-002",
        title="EBS encryption by default is enabled",
        service="ec2",
        severity=Severity.MEDIUM,
        description="Region-level setting that forces every new EBS volume and snapshot copy to be encrypted.",
        remediation="aws ec2 enable-ebs-encryption-by-default --region <region>",
        references=("CIS AWS Foundations 2.2.1",),
    )

    def evaluate(self) -> Iterable[Finding]:
        enabled = self.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        if enabled:
            yield self.passed(self.region, "EBS encryption by default is enabled")
        else:
            yield self.failed(self.region, "EBS encryption by default is disabled")


def _port_range(perm: dict) -> tuple[int, int] | None:
    """Return the (from, to) port range of a permission, or None for 'all traffic'."""
    if perm.get("IpProtocol") == "-1":
        return None
    return perm.get("FromPort", 0), perm.get("ToPort", 65535)


def analyze_ingress(permissions: list[dict]) -> list[dict]:
    """Return a list of internet-exposed rules with their computed severity."""
    exposures = []
    for perm in permissions:
        open_ranges = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") in OPEN_CIDRS]
        open_ranges += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in OPEN_CIDRS]
        if not open_ranges:
            continue
        rng = _port_range(perm)
        if rng is None:
            exposures.append({"ports": "all", "protocol": "all", "cidrs": open_ranges, "severity": "CRITICAL"})
            continue
        lo, hi = rng
        hits = [f"{p}/{name}" for p, name in SENSITIVE_PORTS.items() if lo <= p <= hi]
        if hits:
            severity = "CRITICAL"
        elif hi - lo >= 1000:
            severity = "HIGH"  # wide range, almost certainly unintended
        elif {lo, hi} <= {80, 443}:
            severity = "INFO"  # public web traffic is normal
        else:
            severity = "MEDIUM"
        exposures.append(
            {
                "ports": f"{lo}" if lo == hi else f"{lo}-{hi}",
                "protocol": perm.get("IpProtocol"),
                "cidrs": open_ranges,
                "sensitive": hits,
                "severity": severity,
            }
        )
    return exposures


@register
class SecurityGroupOpenIngress(Check):
    meta = CheckMeta(
        id="EC2-003",
        title="Security groups do not allow unrestricted ingress to sensitive ports",
        service="ec2",
        severity=Severity.CRITICAL,
        description="Ingress from 0.0.0.0/0 or ::/0 to admin or database ports (SSH, RDP, MySQL, ...) "
        "or to all ports is a leading cause of compromise.",
        remediation="Restrict the rule source to known CIDRs or security groups, or use SSM Session Manager "
        "instead of opening SSH/RDP.",
        references=("CIS AWS Foundations 5.2", "CIS AWS Foundations 5.3"),
    )

    def evaluate(self) -> Iterable[Finding]:
        for sg in paginate(self.client("ec2"), "describe_security_groups", "SecurityGroups"):
            exposures = [e for e in analyze_ingress(sg.get("IpPermissions", [])) if e["severity"] != "INFO"]
            resource = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
            if not exposures:
                yield self.passed(resource, "No risky internet-facing ingress rules")
                continue
            worst = max(exposures, key=lambda e: Severity(e["severity"]).rank)
            summary = "; ".join(
                f"{e['protocol']} {e['ports']} from {', '.join(e['cidrs'])}"
                + (f" [{', '.join(e['sensitive'])}]" if e.get("sensitive") else "")
                for e in exposures
            )
            finding = self.failed(resource, f"Open to the internet: {summary}", exposures=exposures)
            # Rule severity is the ceiling; downgrade when only non-sensitive ports are exposed.
            finding.severity = Severity(worst["severity"])
            yield finding


@register
class PublicEbsSnapshots(Check):
    meta = CheckMeta(
        id="EC2-004",
        title="EBS snapshots are not publicly shared",
        service="ec2",
        severity=Severity.CRITICAL,
        description="Public snapshots can be copied by any AWS account, exposing full disk contents.",
        remediation="aws ec2 modify-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission "
        "--operation-type remove --group-names all; then enable 'Block public access for EBS snapshots'.",
    )

    def evaluate(self) -> Iterable[Finding]:
        ec2 = self.client("ec2")
        for snap in paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
            sid = snap["SnapshotId"]
            perms = ec2.describe_snapshot_attribute(SnapshotId=sid, Attribute="createVolumePermission").get(
                "CreateVolumePermissions", []
            )
            if any(p.get("Group") == "all" for p in perms):
                yield self.failed(sid, "Snapshot is public (createVolumePermission: all)")
            else:
                yield self.passed(sid, "Snapshot is private")


@register
class InstanceImdsV2(Check):
    meta = CheckMeta(
        id="EC2-005",
        title="EC2 instances require IMDSv2",
        service="ec2",
        severity=Severity.MEDIUM,
        description="IMDSv1 is vulnerable to SSRF-based credential theft; IMDSv2 requires a session token.",
        remediation="aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required",
        references=("CIS AWS Foundations 5.6",),
    )

    def evaluate(self) -> Iterable[Finding]:
        for reservation in paginate(self.client("ec2"), "describe_instances", "Reservations"):
            for inst in reservation.get("Instances", []):
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                opts = inst.get("MetadataOptions", {})
                if opts.get("HttpEndpoint") == "disabled" or opts.get("HttpTokens") == "required":
                    yield self.passed(inst["InstanceId"], "IMDSv2 enforced (or metadata disabled)")
                else:
                    yield self.failed(inst["InstanceId"], "IMDSv1 is allowed (HttpTokens=optional)")
