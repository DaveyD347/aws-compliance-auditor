"""Run the auditor against a deliberately misconfigured *mocked* AWS account.

No credentials or real AWS account needed: everything runs in moto's in-memory backend.

    pip install -e ".[dev]"
    python examples/demo.py            # writes examples/sample-report.{md,html,json}
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import boto3
from moto import mock_aws

from aws_auditor.clients import ClientFactory
from aws_auditor.report import write_reports
from aws_auditor.scanner import run_audit

REGION = "us-east-1"
OUT = Path(__file__).parent

for var, val in {"AWS_ACCESS_KEY_ID": "demo", "AWS_SECRET_ACCESS_KEY": "demo", "AWS_DEFAULT_REGION": REGION}.items():
    os.environ[var] = val
os.environ.pop("AWS_PROFILE", None)
# Don't preload moto's catalogue of public AMIs (and their ~1,300 snapshots) into the fake account.
os.environ["MOTO_AMIS_PATH"] = str(OUT / "no-amis.json")


def build_environment() -> None:
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    iam = boto3.client("iam", region_name=REGION)
    rds = boto3.client("rds", region_name=REGION)
    ct = boto3.client("cloudtrail", region_name=REGION)

    # S3: one hardened bucket, one leaky marketing bucket, one bucket with a public policy
    locked = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)
    s3.create_bucket(Bucket="acme-prod-data")
    s3.put_public_access_block(Bucket="acme-prod-data", PublicAccessBlockConfiguration=locked)
    s3.put_bucket_versioning(Bucket="acme-prod-data", VersioningConfiguration={"Status": "Enabled"})
    s3.create_bucket(Bucket="acme-marketing-assets")
    s3.put_bucket_acl(Bucket="acme-marketing-assets", ACL="public-read")
    s3.create_bucket(Bucket="acme-backups")
    s3.put_bucket_policy(
        Bucket="acme-backups",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "LegacyPublicRead",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::acme-backups/*",
                    }
                ],
            }
        ),
    )
    s3.create_bucket(Bucket="acme-cloudtrail-logs")
    s3.put_public_access_block(Bucket="acme-cloudtrail-logs", PublicAccessBlockConfiguration=locked)

    # EC2: unencrypted volume, SSH/RDP open to the world, a public snapshot, an IMDSv1 instance
    vol = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=100, Encrypted=False)["VolumeId"]
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=50, Encrypted=True)
    snap = ec2.create_snapshot(VolumeId=vol, Description="db-backup")["SnapshotId"]
    ec2.modify_snapshot_attribute(
        SnapshotId=snap, Attribute="createVolumePermission", OperationType="add", GroupNames=["all"]
    )
    for name, port in (("bastion-ssh", 22), ("windows-rdp", 3389)):
        gid = ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=gid,
            IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            ],
        )
    web = ec2.create_security_group(GroupName="public-web", Description="web")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=web,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)

    # IAM: console user without MFA, an admin '*:*' policy, a weak password policy
    iam.create_user(UserName="jdoe")
    iam.create_login_profile(UserName="jdoe", Password="Correct-Horse-Battery-9")
    iam.create_user(UserName="deploy-bot")
    iam.create_access_key(UserName="deploy-bot")
    admin = iam.create_policy(
        PolicyName="LegacyFullAccess",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )["Policy"]["Arn"]
    iam.attach_user_policy(UserName="deploy-bot", PolicyArn=admin)
    iam.update_account_password_policy(MinimumPasswordLength=8)

    # RDS: a public, unencrypted database
    rds.create_db_instance(
        DBInstanceIdentifier="orders-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="app",
        MasterUserPassword="not-a-real-password",
        AllocatedStorage=20,
        PubliclyAccessible=True,
        StorageEncrypted=False,
    )

    # CloudTrail: a multi-region trail exists but logging is stopped and validation is off
    ct.create_trail(Name="org-trail", S3BucketName="acme-cloudtrail-logs", IsMultiRegionTrail=True)


def main() -> None:
    with mock_aws():
        build_environment()
        result = run_audit(ClientFactory(boto3.session.Session(region_name=REGION)), regions=[REGION])
        for path in write_reports(result, OUT, ["md", "html", "json"], stem="sample-report"):
            print(f"wrote {path}")
        print(f"Grade {result.score.grade}, compliance {result.score.compliance}%, {result.score.failed} failures")


if __name__ == "__main__":
    main()
