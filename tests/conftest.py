"""Shared fixtures. Every test runs against moto's in-memory AWS; no real account is touched."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from aws_auditor.clients import ClientFactory

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    """Make sure a stray real credential can never be used by the test suite."""
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture
def aws():
    with mock_aws():
        yield


@pytest.fixture
def clients(aws) -> ClientFactory:
    return ClientFactory(boto3.session.Session(region_name=REGION))


@pytest.fixture
def ec2(aws):
    return boto3.client("ec2", region_name=REGION)


@pytest.fixture
def s3(aws):
    return boto3.client("s3", region_name=REGION)


@pytest.fixture
def iam(aws):
    return boto3.client("iam", region_name=REGION)


def run(check_cls, clients, region: str = REGION):
    return check_cls(clients, region).run()


def by_resource(findings) -> dict:
    return {f.resource_id: f for f in findings}
