"""End-to-end: build a deliberately insecure environment, audit it, render every report format."""

import json
from datetime import datetime, timezone

import boto3
import pytest
from botocore.exceptions import ClientError
from conftest import REGION

from aws_auditor.checks.base import Check
from aws_auditor.cli import main
from aws_auditor.models import CheckMeta, Finding, Severity, Status
from aws_auditor.report import render_html, render_json, render_markdown, write_reports
from aws_auditor.scanner import run_audit, select_checks
from aws_auditor.scoring import grade_for, score


@pytest.fixture
def insecure_env(aws):
    ec2 = boto3.client("ec2", region_name=REGION)
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=10, Encrypted=False)
    gid = ec2.create_security_group(GroupName="rdp<script>", Description="x")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="leaky-bucket")
    s3.put_bucket_acl(Bucket="leaky-bucket", ACL="public-read")


def test_full_audit(clients, insecure_env):
    result = run_audit(clients, regions=[REGION])
    ids = {f.check_id for f in result.failures}
    assert {"EC2-001", "EC2-003", "S3-002", "IAM-001"} <= ids
    assert result.account_id == "123456789012"
    assert result.score.grade in {"C", "D", "F"}  # criticals cap the grade
    assert result.failures[0].severity is Severity.CRITICAL  # sorted worst-first
    assert result.score.failures_by_severity["CRITICAL"] >= 3


def test_global_checks_run_once_across_regions(clients, insecure_env):
    result = run_audit(clients, regions=[REGION, "eu-west-1"], checks=select_checks(include=["S3-002", "EC2-002"]))
    s3 = [f for f in result.findings if f.check_id == "S3-002"]
    ebs_default = [f for f in result.findings if f.check_id == "EC2-002"]
    assert len(s3) == 1
    assert {f.region for f in ebs_default} == {REGION, "eu-west-1"}


def test_region_discovery(clients):
    result = run_audit(clients, checks=select_checks(include=["EC2-002"]))
    assert len(result.regions) > 5
    assert REGION in result.regions


def test_select_checks():
    assert {c.meta.service for c in select_checks(services=["s3"])} == {"s3"}
    assert [c.meta.id for c in select_checks(include=["iam-001"])] == ["IAM-001"]
    assert "S3-005" not in [c.meta.id for c in select_checks(exclude=["S3-005"])]


def test_min_severity_hides_low_failures(clients, insecure_env):
    result = run_audit(clients, regions=[REGION], min_severity=Severity.HIGH)
    assert all(f.severity.rank >= Severity.HIGH.rank for f in result.failures)


def test_reports_render_and_escape(clients, insecure_env, tmp_path):
    result = run_audit(clients, regions=[REGION])
    md = render_markdown(result)
    assert "# AWS Compliance Audit Report" in md
    assert "leaky-bucket" in md and "## Remediation" in md

    html = render_html(result)
    assert "<script>" not in html.split("<script>\n  document")[0].split("</style>")[1]  # user data escaped
    assert "rdp&lt;script&gt;" in html
    assert "leaky-bucket" in html

    data = json.loads(render_json(result))
    assert data["score"]["failed"] == result.score.failed
    assert {f["status"] for f in data["findings"]} <= {"PASS", "FAIL", "ERROR"}

    paths = write_reports(result, tmp_path, ["md", "html", "json"], stem="r")
    assert sorted(p.name for p in paths) == ["r.html", "r.json", "r.md"]


# --- error handling -------------------------------------------------------------------------


class _Denied(Check):
    meta = CheckMeta("T-001", "denied", "test", Severity.HIGH, "", "")

    def evaluate(self):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "Describe")


class _Boom(Check):
    meta = CheckMeta("T-002", "boom", "test", Severity.HIGH, "", "")

    def evaluate(self):
        raise RuntimeError("bug in check")


def test_access_denied_becomes_error_finding(clients):
    [f] = _Denied(clients, REGION).run()
    assert f.status is Status.ERROR
    assert "insufficient permissions" in f.message


def test_unexpected_exception_does_not_abort_audit(clients):
    result = run_audit(clients, regions=[REGION], checks=[_Boom, *select_checks(include=["EC2-002"])])
    assert any(f.check_id == "T-002" and f.status is Status.ERROR for f in result.findings)
    assert any(f.check_id == "EC2-002" for f in result.findings)
    assert result.score.errors == 1


# --- scoring --------------------------------------------------------------------------------


def _f(sev, status, check="X"):
    return Finding(check, "x", "s", sev, status, "r", "global", "")


def test_score_weighting():
    s = score([_f(Severity.LOW, Status.FAIL, "A"), _f(Severity.CRITICAL, Status.PASS, "B")])
    assert s.compliance == round(100 * 10 / 11, 1)
    assert s.risk == 1
    assert s.grade == "A"

    s = score([_f(Severity.CRITICAL, Status.FAIL)] + [_f(Severity.CRITICAL, Status.PASS)] * 20)
    assert s.compliance > 90 and s.grade == "C"  # capped by the critical failure


def test_score_is_per_check_not_per_resource():
    # 1000 passing snapshots must not hide a failing root-MFA control
    many = [_f(Severity.CRITICAL, Status.PASS, "SNAP")] * 1000
    s = score(many + [_f(Severity.CRITICAL, Status.FAIL, "ROOT")])
    assert s.compliance == 50.0
    assert s.grade == "F"


def test_score_ignores_errors_and_handles_empty():
    assert score([]).compliance == 100.0
    assert score([_f(Severity.HIGH, Status.ERROR)]).errors == 1


def test_grade_bands():
    assert [grade_for(x, False) for x in (95, 85, 75, 65, 10)] == ["A", "B", "C", "D", "F"]


# --- CLI ------------------------------------------------------------------------------------


def test_cli_end_to_end(insecure_env, tmp_path, capsys):
    code = main(["--regions", REGION, "--output-dir", str(tmp_path), "--format", "md,json", "--fail-on", "critical"])
    assert code == 1
    out = capsys.readouterr().out
    assert "Grade" in out and "EC2-003" in out
    assert len(list(tmp_path.glob("*.md"))) == 1 and len(list(tmp_path.glob("*.json"))) == 1


def test_cli_passes_when_threshold_not_met(aws, tmp_path):
    code = main(["--regions", REGION, "--checks", "S3-002", "--output-dir", str(tmp_path), "--fail-on", "high"])
    assert code == 0


def test_cli_bad_args(capsys):
    assert main(["--format", "pdf"]) == 2
    assert main(["--fail-on", "apocalyptic"]) == 2
    assert main(["--checks", "NOPE-1"]) == 2


def test_cli_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    assert "S3-001" in capsys.readouterr().out


def test_result_timestamps_are_utc(clients):
    result = run_audit(clients, regions=[REGION], checks=select_checks(include=["EC2-002"]))
    assert result.finished_at.tzinfo == timezone.utc
    assert result.finished_at >= result.started_at
    assert isinstance(result.started_at, datetime)
