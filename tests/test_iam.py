import json
from datetime import datetime, timedelta, timezone

from conftest import by_resource, run

from aws_auditor.checks.iam import (
    AccessKeyRotation,
    ConsoleUsersMfa,
    CustomerManagedAdminPolicies,
    PasswordPolicy,
    RootAccessKeys,
    RootMfa,
    grants_full_admin,
)
from aws_auditor.models import Status


def test_root_checks_default_account(clients):
    # moto's fresh account has no root MFA and no root keys
    [mfa] = run(RootMfa, clients)
    [keys] = run(RootAccessKeys, clients)
    assert mfa.status is Status.FAIL
    assert keys.status is Status.PASS


def test_console_users_without_mfa(clients, iam):
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r-Secret-Passw0rd!")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Sup3r-Secret-Passw0rd!")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(
        UserName="bob", SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321"
    )
    iam.create_user(UserName="svc-no-console")

    res = by_resource(run(ConsoleUsersMfa, clients))
    assert res["alice"].status is Status.FAIL
    assert res["bob"].status is Status.PASS
    assert "svc-no-console" not in res


def test_access_key_age(clients, iam):
    iam.create_user(UserName="ci-bot")
    iam.create_access_key(UserName="ci-bot")
    [fresh] = run(AccessKeyRotation, clients)
    assert fresh.status is Status.PASS

    check = AccessKeyRotation(clients, "us-east-1")
    check.now = datetime.now(timezone.utc) + timedelta(days=120)
    [stale] = check.run()
    assert stale.status is Status.FAIL
    assert stale.resource_id == "ci-bot (key 1)"
    assert stale.details["age_days"] >= 119


def test_password_policy(clients, iam):
    [missing] = run(PasswordPolicy, clients)
    assert missing.status is Status.FAIL

    iam.update_account_password_policy(MinimumPasswordLength=8)
    [weak] = run(PasswordPolicy, clients)
    assert weak.status is Status.FAIL
    assert "minimum length 8" in weak.message

    iam.update_account_password_policy(MinimumPasswordLength=16, PasswordReusePrevention=24)
    [ok] = run(PasswordPolicy, clients)
    assert ok.status is Status.PASS


def test_admin_policies(clients, iam):
    admin_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    scoped_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    iam.create_user(UserName="u")
    for name, doc in (("god-mode", admin_doc), ("read-s3", scoped_doc), ("unattached-admin", admin_doc)):
        arn = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
        if name != "unattached-admin":
            iam.attach_user_policy(UserName="u", PolicyArn=arn)

    res = by_resource(run(CustomerManagedAdminPolicies, clients))
    assert res["god-mode"].status is Status.FAIL
    assert res["read-s3"].status is Status.PASS
    assert "unattached-admin" not in res


def test_grants_full_admin_shapes():
    assert grants_full_admin({"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}})
    assert not grants_full_admin({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    assert not grants_full_admin({"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]})
