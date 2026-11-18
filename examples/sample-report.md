# AWS Compliance Audit Report

**Account:** `123456789012`  
**Regions:** us-east-1  
**Generated:** 2026-11-18 22:16:54 UTC  
**Duration:** 2.8s

## Summary

| Grade | Compliance | Risk score | Passed | Failed | Errors |
|:-:|:-:|:-:|:-:|:-:|:-:|
| **F** | 30.6% | 155 | 14 | 26 | 0 |

| Severity | Failures |
|---|--:|
| 🔴 CRITICAL | 6 |
| 🟠 HIGH | 9 |
| 🟡 MEDIUM | 7 |
| 🔵 LOW | 4 |

## Checks

| ID | Check | Severity | Result | Pass | Fail |
|---|---|---|:-:|--:|--:|
| CT-001 | A multi-region CloudTrail trail is logging | HIGH | ❌ | 0 | 1 |
| CT-002 | CloudTrail log file validation is enabled | LOW | ❌ | 0 | 1 |
| EC2-001 | EBS volumes are encrypted | HIGH | ❌ | 1 | 2 |
| EC2-002 | EBS encryption by default is enabled | MEDIUM | ❌ | 0 | 1 |
| EC2-003 | Security groups do not allow unrestricted ingress to sensitive ports | CRITICAL | ❌ | 2 | 2 |
| EC2-004 | EBS snapshots are not publicly shared | CRITICAL | ❌ | 0 | 1 |
| EC2-005 | EC2 instances require IMDSv2 | MEDIUM | ❌ | 0 | 1 |
| IAM-001 | Root account has MFA enabled | CRITICAL | ❌ | 0 | 1 |
| IAM-002 | Root account has no access keys | CRITICAL | ✅ | 1 | 0 |
| IAM-003 | IAM users with console access have MFA | HIGH | ❌ | 0 | 1 |
| IAM-004 | Active access keys are rotated within 90 days | MEDIUM | ✅ | 1 | 0 |
| IAM-005 | Account password policy meets the baseline | MEDIUM | ❌ | 0 | 1 |
| IAM-006 | No attached customer-managed policies grant full '*:*' admin | HIGH | ❌ | 0 | 1 |
| RDS-001 | RDS instances are not publicly accessible | HIGH | ❌ | 0 | 1 |
| RDS-002 | RDS instance storage is encrypted | HIGH | ❌ | 0 | 1 |
| S3-001 | S3 bucket Block Public Access is fully enabled | HIGH | ❌ | 2 | 2 |
| S3-002 | S3 bucket ACL does not grant public access | CRITICAL | ❌ | 3 | 1 |
| S3-003 | S3 bucket policy does not allow anonymous access | CRITICAL | ❌ | 3 | 1 |
| S3-004 | S3 bucket has default encryption configured | MEDIUM | ❌ | 0 | 4 |
| S3-005 | S3 bucket versioning is enabled | LOW | ❌ | 1 | 3 |

## Failed findings

| Severity | ID | Region | Resource | Issue |
|---|---|---|---|---|
| 🔴 CRITICAL | EC2-003 | us-east-1 | `sg-95e328c65c3f092ff (windows-rdp)` | Open to the internet: tcp 3389 from 0.0.0.0/0 [3389/RDP] |
| 🔴 CRITICAL | EC2-003 | us-east-1 | `sg-e19977b8a00818d33 (bastion-ssh)` | Open to the internet: tcp 22 from 0.0.0.0/0 [22/SSH] |
| 🔴 CRITICAL | EC2-004 | us-east-1 | `snap-75b036760536a7420` | Snapshot is public (createVolumePermission: all) |
| 🔴 CRITICAL | IAM-001 | global | `<root_account>` | Root MFA is NOT enabled |
| 🔴 CRITICAL | S3-002 | global | `acme-marketing-assets` | ACL grants public access (AllUsers:READ) |
| 🔴 CRITICAL | S3-003 | global | `acme-backups` | Policy statement(s) LegacyPublicRead allow Principal '*' |
| 🟠 HIGH | CT-001 | global | `cloudtrail` | No multi-region trail is actively logging |
| 🟠 HIGH | EC2-001 | us-east-1 | `vol-79092df06ec43046f` | Volume is not encrypted |
| 🟠 HIGH | EC2-001 | us-east-1 | `vol-c96eca516db96b91d` | Volume is not encrypted |
| 🟠 HIGH | IAM-003 | global | `jdoe` | Console password enabled without MFA |
| 🟠 HIGH | IAM-006 | global | `LegacyFullAccess` | Grants '*:*' and is attached to 1 entities |
| 🟠 HIGH | RDS-001 | us-east-1 | `orders-db` | Instance is publicly accessible |
| 🟠 HIGH | RDS-002 | us-east-1 | `orders-db` | Storage is NOT encrypted |
| 🟠 HIGH | S3-001 | global | `acme-backups` | Block Public Access settings disabled: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets |
| 🟠 HIGH | S3-001 | global | `acme-marketing-assets` | Block Public Access settings disabled: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets |
| 🟡 MEDIUM | EC2-002 | us-east-1 | `us-east-1` | EBS encryption by default is disabled |
| 🟡 MEDIUM | EC2-005 | us-east-1 | `i-1dede73d2f9f7dd04` | IMDSv1 is allowed (HttpTokens=optional) |
| 🟡 MEDIUM | IAM-005 | global | `account-password-policy` | minimum length 8 < 14; reuse prevention 0 < 24 |
| 🟡 MEDIUM | S3-004 | global | `acme-backups` | No default encryption configured |
| 🟡 MEDIUM | S3-004 | global | `acme-cloudtrail-logs` | No default encryption configured |
| 🟡 MEDIUM | S3-004 | global | `acme-marketing-assets` | No default encryption configured |
| 🟡 MEDIUM | S3-004 | global | `acme-prod-data` | No default encryption configured |
| 🔵 LOW | CT-002 | global | `org-trail` | Log file validation disabled |
| 🔵 LOW | S3-005 | global | `acme-backups` | Versioning is Disabled |
| 🔵 LOW | S3-005 | global | `acme-cloudtrail-logs` | Versioning is Disabled |
| 🔵 LOW | S3-005 | global | `acme-marketing-assets` | Versioning is Disabled |

## Remediation

### EC2-003: Security groups do not allow unrestricted ingress to sensitive ports

Restrict the rule source to known CIDRs or security groups, or use SSM Session Manager instead of opening SSH/RDP.

### EC2-004: EBS snapshots are not publicly shared

aws ec2 modify-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission --operation-type remove --group-names all; then enable 'Block public access for EBS snapshots'.

### IAM-001: Root account has MFA enabled

Sign in as root and enable a hardware or virtual MFA device under Security credentials.

### S3-002: S3 bucket ACL does not grant public access

Remove the public grants (aws s3api put-bucket-acl --bucket <name> --acl private) and enable Object Ownership 'BucketOwnerEnforced' to disable ACLs entirely.

### S3-003: S3 bucket policy does not allow anonymous access

Restrict the Principal to specific accounts/roles or add a Condition (e.g. aws:SourceVpce, aws:PrincipalOrgID).

### CT-001: A multi-region CloudTrail trail is logging

aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> --is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name org-trail

### EC2-001: EBS volumes are encrypted

Snapshot the volume, copy the snapshot with --encrypted, create a new volume from it and swap it in. Enable EBS encryption by default to prevent recurrence.

### IAM-003: IAM users with console access have MFA

Enforce MFA for the user, or remove the login profile if console access is not needed.

### IAM-006: No attached customer-managed policies grant full '*:*' admin

Replace the policy with a scoped one, or use the AWS-managed AdministratorAccess policy only for a small, MFA-protected break-glass role.

### RDS-001: RDS instances are not publicly accessible

aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible --apply-immediately

### RDS-002: RDS instance storage is encrypted

Encryption can't be enabled in place: snapshot the instance, copy the snapshot with a KMS key, and restore a new instance from the encrypted copy.

### S3-001: S3 bucket Block Public Access is fully enabled

aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

### EC2-002: EBS encryption by default is enabled

aws ec2 enable-ebs-encryption-by-default --region <region>

### EC2-005: EC2 instances require IMDSv2

aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required

### IAM-005: Account password policy meets the baseline

aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24

### S3-004: S3 bucket has default encryption configured

aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'

### CT-002: CloudTrail log file validation is enabled

aws cloudtrail update-trail --name <trail> --enable-log-file-validation

### S3-005: S3 bucket versioning is enabled

aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled
