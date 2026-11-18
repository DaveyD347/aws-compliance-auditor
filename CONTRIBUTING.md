# Contributing

New rules are the most useful contribution. Each one is a small class.

## Adding a check

1. Pick the module for the service in `src/aws_auditor/checks/` (or add a new one and import it in `checks/__init__.py`).
2. Subclass `Check`, fill in `meta`, implement `evaluate()`, and decorate with `@register`:

```python
@register
class KmsKeyRotation(Check):
    meta = CheckMeta(
        id="KMS-001",
        title="Customer-managed KMS keys have rotation enabled",
        service="kms",
        severity=Severity.MEDIUM,
        description="Automatic rotation limits how much data a single key version protects.",
        remediation="aws kms enable-key-rotation --key-id <id>",
        references=("CIS AWS Foundations 3.6",),
    )

    def evaluate(self):
        kms = self.client("kms")
        for key in paginate(kms, "list_keys", "Keys"):
            ...
            yield self.passed(key_id, "Rotation enabled")  # or self.failed(...)
```

3. Rules for checks:
   - **Read-only API calls only.** Add any new permission to `docs/iam-policy.json`.
   - Always paginate with `paginate()`; never assume one page.
   - Yield one finding per resource so reports show what passed as well as what failed.
   - Let unexpected `ClientError`s propagate: `Check.run()` turns them into `ERROR` findings.
     Catch only the "not configured" codes that mean pass/fail (e.g. `NoSuchBucketPolicy`).
   - Set `global_service=True` for account-wide services (IAM, S3, CloudTrail) so they run once.
4. Add tests in `tests/` using the moto fixtures in `conftest.py`, covering at least one passing
   and one failing resource.

## Dev loop

```bash
pip install -e ".[dev]"
pytest
ruff check . && ruff format .
python examples/demo.py   # regenerate sample reports
```

Tests never touch a real AWS account: `conftest.py` forces fake credentials and wraps every test in `mock_aws()`.
