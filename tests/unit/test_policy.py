from guardrail.models import CanonicalResource, Policy, PolicyViolation
from guardrail.policy import evaluate_policies


def bucket(bucket_name: str, **attributes) -> CanonicalResource:
    return CanonicalResource(
        resource_type="aws_s3_bucket",
        identity={"bucket": bucket_name},
        attributes=attributes,
    )


COMPLIANT = {
    "encryption": {"sse_algorithm": "aws:kms", "kms_master_key_id": "alias/guardrail"},
    "versioning": {"status": "Enabled", "mfa_delete": "Disabled"},
    "public_access_block": {
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": True,
    },
}


def test_fully_compliant_resource_produces_no_violations():
    assert evaluate_policies([bucket("guardrail-example-data", **COMPLIANT)]) == []


def test_encryption_missing_raises_encryption_violation():
    resource = bucket(
        "guardrail-example-data",
        encryption={},
        versioning={"status": "Enabled"},
        public_access_block={
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
    )

    violations = evaluate_policies([resource])

    assert len(violations) == 1
    assert violations[0].policy is Policy.S3_ENCRYPTION


def test_versioning_missing_raises_versioning_violation():
    resource = bucket(
        "guardrail-example-data",
        encryption={"sse_algorithm": "AES256"},
        versioning={},
        public_access_block={
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
    )

    violations = evaluate_policies([resource])

    assert len(violations) == 1
    assert violations[0].policy is Policy.S3_VERSIONING


def test_absent_attributes_count_as_not_configured():
    resource = bucket("guardrail-example-data", bucket="guardrail-example-data")

    violations = evaluate_policies([resource])

    assert {violation.policy for violation in violations} == {
        Policy.S3_ENCRYPTION,
        Policy.S3_VERSIONING,
        Policy.S3_BLOCK_PUBLIC_ACCESS,
    }


def test_encryption_and_versioning_both_missing_produce_both_violations():
    resource = bucket("guardrail-example-data")

    violations = evaluate_policies([resource])

    assert {violation.policy for violation in violations} == {
        Policy.S3_ENCRYPTION,
        Policy.S3_VERSIONING,
        Policy.S3_BLOCK_PUBLIC_ACCESS,
    }


def test_suspended_versioning_is_a_violation():
    resource = bucket(
        "guardrail-example-data",
        encryption={"sse_algorithm": "AES256"},
        versioning={"status": "Suspended"},
        public_access_block={
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
    )

    violations = evaluate_policies([resource])

    assert len(violations) == 1
    assert violations[0].policy is Policy.S3_VERSIONING


def test_compliant_encryption_but_missing_versioning_only_raises_versioning():
    resource = bucket(
        "guardrail-example-data",
        encryption={"sse_algorithm": "AES256"},
        versioning={},
        public_access_block={
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
    )

    violations = evaluate_policies([resource])

    assert [violation.policy for violation in violations] == [Policy.S3_VERSIONING]


def test_violation_contains_resource_identity():
    violations = evaluate_policies(
        [
            bucket(
                "guardrail-public",
                encryption={},
                public_access_block={
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True,
                },
            )
        ]
    )

    assert violations[0].identity == {"bucket": "guardrail-public"}


def test_violation_contains_policy_identifier():
    violations = evaluate_policies(
        [
            bucket(
                "guardrail-public",
                encryption={},
                public_access_block={
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True,
                },
            )
        ]
    )

    assert violations[0].policy.value == "s3-encryption"


def test_violation_contains_expected_observed_and_reason():
    [violation] = evaluate_policies(
        [
            bucket(
                "guardrail-public",
                encryption={},
                versioning={"status": "Enabled"},
                public_access_block={
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True,
                },
            )
        ]
    )

    assert "encryption" in violation.expected
    assert violation.observed == {}
    assert "no server-side encryption" in violation.reason


def test_unconfigured_public_access_block_is_a_violation():
    resource = bucket(
        "guardrail-example-data",
        encryption={"sse_algorithm": "AES256"},
        versioning={"status": "Enabled"},
        public_access_block={},
    )

    violations = evaluate_policies([resource])

    assert len(violations) == 1
    assert violations[0].policy is Policy.S3_BLOCK_PUBLIC_ACCESS
    assert violations[0].observed == {}
    assert "not fully enabled" in violations[0].reason


def test_partially_enabled_public_access_block_is_a_violation():
    resource = bucket(
        "guardrail-example-data",
        encryption={"sse_algorithm": "AES256"},
        versioning={"status": "Enabled"},
        public_access_block={
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": False,
            "restrict_public_buckets": True,
        },
    )

    violations = evaluate_policies([resource])

    assert len(violations) == 1
    assert violations[0].policy is Policy.S3_BLOCK_PUBLIC_ACCESS
    assert violations[0].observed == {
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": False,
        "restrict_public_buckets": True,
    }


def test_multiple_resources_are_deterministically_ordered():
    resources = [
        bucket("zzz-bucket", encryption={}, versioning={"status": "Enabled"}),
        bucket("aaa-bucket", encryption={}, versioning={"status": "Enabled"}),
        bucket("mmm-bucket", encryption={}, versioning={}),
    ]

    violations = evaluate_policies(resources)

    assert [violation.identity["bucket"] for violation in violations] == [
        "aaa-bucket",
        "aaa-bucket",
        "mmm-bucket",
        "mmm-bucket",
        "mmm-bucket",
        "zzz-bucket",
        "zzz-bucket",
    ]
    assert [violation.policy for violation in violations] == [
        Policy.S3_BLOCK_PUBLIC_ACCESS,
        Policy.S3_ENCRYPTION,
        Policy.S3_BLOCK_PUBLIC_ACCESS,
        Policy.S3_ENCRYPTION,
        Policy.S3_VERSIONING,
        Policy.S3_BLOCK_PUBLIC_ACCESS,
        Policy.S3_ENCRYPTION,
    ]


def test_policy_evaluation_is_independent_of_terraform_address():
    expected = CanonicalResource(
        resource_type="aws_s3_bucket",
        identity={"bucket": "guardrail-example-data"},
        attributes=dict(COMPLIANT),
        terraform_address="aws_s3_bucket.data",
    )
    observed = CanonicalResource(
        resource_type="aws_s3_bucket",
        identity={"bucket": "guardrail-example-data"},
        attributes=dict(COMPLIANT),
        terraform_address=None,
    )

    assert evaluate_policies([expected]) == evaluate_policies([observed]) == []


def test_policy_evaluation_is_deterministic_across_runs():
    resources = [
        bucket("bbb-bucket", versioning={}),
        bucket("aaa-bucket", encryption={}),
    ]

    first = evaluate_policies(resources)
    second = evaluate_policies(resources)

    assert first == second
    assert len(first) == 6