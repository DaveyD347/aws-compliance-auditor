import json

from conftest import by_resource, run

from aws_auditor.checks.s3 import (
    S3DefaultEncryption,
    S3PublicAccessBlock,
    S3PublicAcl,
    S3PublicPolicy,
    S3Versioning,
    _policy_public_statements,
)
from aws_auditor.models import Status

LOCKED = {flag: True for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


def test_public_access_block(clients, s3):
    s3.create_bucket(Bucket="locked")
    s3.put_public_access_block(Bucket="locked", PublicAccessBlockConfiguration=LOCKED)
    s3.create_bucket(Bucket="partial")
    s3.put_public_access_block(
        Bucket="partial", PublicAccessBlockConfiguration={**LOCKED, "RestrictPublicBuckets": False}
    )
    s3.create_bucket(Bucket="none")

    res = by_resource(run(S3PublicAccessBlock, clients))
    assert res["locked"].status is Status.PASS
    assert res["partial"].status is Status.FAIL
    assert res["partial"].details["missing"] == ["RestrictPublicBuckets"]
    assert res["none"].status is Status.FAIL
    assert res["none"].region == "global"


def test_public_acl(clients, s3):
    s3.create_bucket(Bucket="private")
    s3.create_bucket(Bucket="public-read")
    s3.put_bucket_acl(Bucket="public-read", ACL="public-read")

    res = by_resource(run(S3PublicAcl, clients))
    assert res["private"].status is Status.PASS
    assert res["public-read"].status is Status.FAIL
    assert "AllUsers:READ" in res["public-read"].message
    assert res["public-read"].remediation  # failures carry remediation text


def test_public_policy(clients, s3):
    s3.create_bucket(Bucket="no-policy")
    s3.create_bucket(Bucket="open")
    s3.put_bucket_policy(
        Bucket="open",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Anyone",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::open/*",
                    }
                ],
            }
        ),
    )
    s3.create_bucket(Bucket="conditioned")
    s3.put_bucket_policy(
        Bucket="conditioned",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::conditioned/*",
                        "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-123"}},
                    }
                ],
            }
        ),
    )

    res = by_resource(run(S3PublicPolicy, clients))
    assert res["no-policy"].status is Status.PASS
    assert res["open"].status is Status.FAIL
    assert res["conditioned"].status is Status.PASS


def test_policy_parser_handles_principal_shapes():
    policy = {
        "Statement": [
            {"Sid": "a", "Effect": "Allow", "Principal": {"AWS": "*"}},
            {"Sid": "b", "Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::1:root", "*"]}},
            {"Sid": "c", "Effect": "Deny", "Principal": "*"},
            {"Sid": "d", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}},
        ]
    }
    assert _policy_public_statements(policy) == ["a", "b"]
    assert _policy_public_statements({"Statement": {"Effect": "Allow", "Principal": "*"}}) == ["#0"]


def test_default_encryption(clients, s3):
    s3.create_bucket(Bucket="kms-bucket")
    s3.put_bucket_encryption(
        Bucket="kms-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    res = by_resource(run(S3DefaultEncryption, clients))
    assert res["kms-bucket"].status is Status.PASS
    assert res["kms-bucket"].details["algorithms"] == ["aws:kms"]


def test_versioning(clients, s3):
    s3.create_bucket(Bucket="versioned")
    s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})
    s3.create_bucket(Bucket="plain")
    res = by_resource(run(S3Versioning, clients))
    assert res["versioned"].status is Status.PASS
    assert res["plain"].status is Status.FAIL


def test_buckets_in_other_regions(clients, aws):
    import boto3

    boto3.client("s3", region_name="eu-west-1").create_bucket(
        Bucket="eu-bucket", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"}
    )
    res = by_resource(run(S3Versioning, clients))
    assert res["eu-bucket"].status is Status.FAIL


def test_no_buckets_yields_nothing(clients):
    assert run(S3PublicAcl, clients) == []
