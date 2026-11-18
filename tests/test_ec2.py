from conftest import REGION, by_resource, run

from aws_auditor.checks.ec2 import (
    EbsEncryptionByDefault,
    EbsVolumeEncryption,
    InstanceImdsV2,
    PublicEbsSnapshots,
    SecurityGroupOpenIngress,
    analyze_ingress,
)
from aws_auditor.models import Severity, Status

AZ = f"{REGION}a"


def test_volume_encryption(clients, ec2):
    enc = ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=True)["VolumeId"]
    plain = ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=False)["VolumeId"]
    res = by_resource(run(EbsVolumeEncryption, clients))
    assert res[enc].status is Status.PASS
    assert res[plain].status is Status.FAIL
    assert res[plain].region == REGION
    assert res[plain].details["size_gib"] == 8


def test_encryption_by_default(clients, ec2):
    [finding] = run(EbsEncryptionByDefault, clients)
    assert finding.status is Status.FAIL
    ec2.enable_ebs_encryption_by_default()
    [finding] = run(EbsEncryptionByDefault, clients)
    assert finding.status is Status.PASS


def _sg(ec2, name, perms):
    gid = ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
    if perms:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return f"{gid} ({name})"


def _rule(port_from, port_to, cidr="0.0.0.0/0", proto="tcp"):
    return {"IpProtocol": proto, "FromPort": port_from, "ToPort": port_to, "IpRanges": [{"CidrIp": cidr}]}


def test_security_groups(clients, ec2):
    ssh = _sg(ec2, "ssh-open", [_rule(22, 22)])
    web = _sg(ec2, "web", [_rule(443, 443), _rule(80, 80)])
    internal = _sg(ec2, "internal-db", [_rule(5432, 5432, cidr="10.0.0.0/16")])
    wide = _sg(ec2, "wide", [_rule(8000, 9100)])
    odd = _sg(ec2, "odd-port", [_rule(8443, 8443)])
    v6 = _sg(
        ec2,
        "rdp-v6",
        [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
    )

    res = by_resource(run(SecurityGroupOpenIngress, clients))
    assert res[ssh].status is Status.FAIL and res[ssh].severity is Severity.CRITICAL
    assert "22/SSH" in res[ssh].message
    assert res[web].status is Status.PASS
    assert res[internal].status is Status.PASS
    assert res[wide].status is Status.FAIL and res[wide].severity is Severity.HIGH
    assert res[odd].status is Status.FAIL and res[odd].severity is Severity.MEDIUM
    assert res[v6].status is Status.FAIL and res[v6].severity is Severity.CRITICAL


def test_analyze_ingress_all_traffic():
    [exp] = analyze_ingress([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert exp["severity"] == "CRITICAL" and exp["ports"] == "all"


def test_analyze_ingress_range_covering_sensitive_port():
    [exp] = analyze_ingress([_rule(3000, 3400)])
    assert exp["severity"] == "CRITICAL"
    assert "3306/MySQL" in exp["sensitive"] and "3389/RDP" in exp["sensitive"]


def test_public_snapshot(clients, ec2):
    vol = ec2.create_volume(AvailabilityZone=AZ, Size=1)["VolumeId"]
    private = ec2.create_snapshot(VolumeId=vol)["SnapshotId"]
    public = ec2.create_snapshot(VolumeId=vol)["SnapshotId"]
    ec2.modify_snapshot_attribute(
        SnapshotId=public, Attribute="createVolumePermission", OperationType="add", GroupNames=["all"]
    )
    res = by_resource(run(PublicEbsSnapshots, clients))
    assert res[private].status is Status.PASS
    assert res[public].status is Status.FAIL


def test_imds(clients, ec2):
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    v1 = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    v2 = ec2.run_instances(
        ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"}
    )["Instances"][0]["InstanceId"]
    res = by_resource(run(InstanceImdsV2, clients))
    assert res[v1].status is Status.FAIL
    assert res[v2].status is Status.PASS
