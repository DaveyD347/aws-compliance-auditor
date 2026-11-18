import boto3
from conftest import REGION, by_resource, run

from aws_auditor.checks.logging_rds import (
    CloudTrailLogValidation,
    CloudTrailMultiRegion,
    RdsEncryption,
    RdsPublicAccess,
)
from aws_auditor.models import Status


def test_cloudtrail(clients, s3):
    [none] = run(CloudTrailMultiRegion, clients)
    assert none.status is Status.FAIL

    s3.create_bucket(Bucket="trail-logs")
    ct = boto3.client("cloudtrail", region_name=REGION)
    ct.create_trail(Name="org", S3BucketName="trail-logs", IsMultiRegionTrail=True, EnableLogFileValidation=True)
    [stopped] = run(CloudTrailMultiRegion, clients)
    assert stopped.status is Status.FAIL  # exists but not logging

    ct.start_logging(Name="org")
    ct.create_trail(Name="legacy", S3BucketName="trail-logs")
    [ok] = run(CloudTrailMultiRegion, clients)
    assert ok.status is Status.PASS

    res = by_resource(run(CloudTrailLogValidation, clients))
    assert res["org"].status is Status.PASS
    assert res["legacy"].status is Status.FAIL


def test_rds(clients, aws):
    rds = boto3.client("rds", region_name=REGION)
    common = dict(
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="Passw0rd-not-real",
        AllocatedStorage=20,
    )
    rds.create_db_instance(
        DBInstanceIdentifier="public-plain", PubliclyAccessible=True, StorageEncrypted=False, **common
    )
    rds.create_db_instance(
        DBInstanceIdentifier="private-enc", PubliclyAccessible=False, StorageEncrypted=True, **common
    )

    public = by_resource(run(RdsPublicAccess, clients))
    assert public["public-plain"].status is Status.FAIL
    assert public["private-enc"].status is Status.PASS

    enc = by_resource(run(RdsEncryption, clients))
    assert enc["public-plain"].status is Status.FAIL
    assert enc["private-enc"].status is Status.PASS
