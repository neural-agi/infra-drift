import pytest

from guardrail.drift import detect_drift
from guardrail.models import CanonicalResource, ChangeType, DriftFinding
from guardrail.models.drift import ABSENT, DuplicateResourceError


def bucket(bucket_name: str, **attributes) -> CanonicalResource:
    return CanonicalResource(
        resource_type="aws_s3_bucket",
        identity={"bucket": bucket_name},
        attributes=attributes,
    )


def test_identical_resources_produce_no_drift():
    expected = [
        bucket(
            "guardrail-example-data",
            region="us-east-1",
            tags={"Environment": "production"},
        )
    ]
    observed = [
        bucket(
            "guardrail-example-data",
            region="us-east-1",
            tags={"Environment": "production"},
        )
    ]

    assert detect_drift(expected, observed) == []


def test_changed_scalar_attribute():
    findings = detect_drift(
        [bucket("guardrail-example-data", region="us-east-1")],
        [bucket("guardrail-example-data", region="us-west-2")],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.ATTRIBUTE_CHANGED
    assert finding.path == ("region",)
    assert finding.expected == "us-east-1"
    assert finding.observed == "us-west-2"


def test_tag_added():
    findings = detect_drift(
        [bucket("guardrail-example-data", tags={})],
        [bucket("guardrail-example-data", tags={"Environment": "production"})],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.ATTRIBUTE_ADDED
    assert finding.path == ("tags", "Environment")
    assert finding.expected is ABSENT
    assert finding.observed == "production"


def test_tag_removed():
    findings = detect_drift(
        [bucket("guardrail-example-data", tags={"Environment": "production"})],
        [bucket("guardrail-example-data", tags={})],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.ATTRIBUTE_REMOVED
    assert finding.path == ("tags", "Environment")
    assert finding.expected == "production"
    assert finding.observed is ABSENT


def test_tag_value_changed():
    findings = detect_drift(
        [bucket("guardrail-example-data", tags={"Environment": "production"})],
        [bucket("guardrail-example-data", tags={"Environment": "staging"})],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.ATTRIBUTE_CHANGED
    assert finding.path == ("tags", "Environment")
    assert finding.expected == "production"
    assert finding.observed == "staging"


def test_nested_canonical_attribute_changed():
    findings = detect_drift(
        [
            bucket(
                "guardrail-example-data",
                encryption={"sse_algorithm": "AES256"},
            )
        ],
        [
            bucket(
                "guardrail-example-data",
                encryption={
                    "sse_algorithm": "aws:kms",
                    "kms_master_key_id": "alias/guardrail",
                },
            )
        ],
    )

    assert len(findings) == 2
    by_path = {finding.path: finding for finding in findings}
    assert by_path[("encryption", "sse_algorithm")].change_type is ChangeType.ATTRIBUTE_CHANGED
    assert by_path[("encryption", "sse_algorithm")].expected == "AES256"
    assert by_path[("encryption", "sse_algorithm")].observed == "aws:kms"
    assert by_path[("encryption", "kms_master_key_id")].change_type is ChangeType.ATTRIBUTE_ADDED
    assert by_path[("encryption", "kms_master_key_id")].observed == "alias/guardrail"


def test_expected_resource_missing():
    findings = detect_drift(
        [bucket("guardrail-deleted", region="us-east-1")],
        [],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.RESOURCE_MISSING
    assert finding.identity == {"bucket": "guardrail-deleted"}
    assert finding.path == ()
    assert finding.expected == bucket("guardrail-deleted", region="us-east-1")
    assert finding.observed is ABSENT


def test_unexpected_observed_resource():
    findings = detect_drift(
        [],
        [bucket("guardrail-orphaned", region="us-east-1")],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.RESOURCE_UNEXPECTED
    assert finding.identity == {"bucket": "guardrail-orphaned"}
    assert finding.path == ()
    assert finding.expected is ABSENT
    assert finding.observed == bucket("guardrail-orphaned", region="us-east-1")


def test_different_terraform_address_same_identity_produces_no_drift():
    expected = [
        CanonicalResource(
            resource_type="aws_s3_bucket",
            identity={"bucket": "guardrail-example-data"},
            attributes={"region": "us-east-1", "tags": {"Environment": "production"}},
            terraform_address="aws_s3_bucket.data",
        )
    ]
    observed = [
        CanonicalResource(
            resource_type="aws_s3_bucket",
            identity={"bucket": "guardrail-example-data"},
            attributes={"region": "us-east-1", "tags": {"Environment": "production"}},
            terraform_address=None,
        )
    ]

    assert detect_drift(expected, observed) == []


def test_multiple_differences_in_one_resource_all_reported():
    findings = detect_drift(
        [bucket("guardrail-example-data", region="us-east-1", tags={"A": "1", "B": "2"})],
        [bucket("guardrail-example-data", region="us-west-2", tags={"A": "1"})],
    )

    assert len(findings) == 2
    paths = {finding.path for finding in findings}
    assert paths == {("region",), ("tags", "B")}
    assert all(
        finding.change_type in (ChangeType.ATTRIBUTE_CHANGED, ChangeType.ATTRIBUTE_REMOVED)
        for finding in findings
    )


def test_multiple_differences_are_deterministically_ordered():
    expected = [
        bucket("aaa-bucket", tags={"a": "1", "b": "2"}),
        bucket("zzz-bucket", region="us-east-1"),
    ]
    observed = [
        bucket("aaa-bucket", tags={"a": "1"}),
        bucket("zzz-bucket", region="us-west-2"),
    ]

    first = detect_drift(expected, observed)
    second = detect_drift(expected, observed)

    assert first == second
    assert len(first) == 2
    assert [finding.identity["bucket"] for finding in first] == [
        "aaa-bucket",
        "zzz-bucket",
    ]
    assert first[0].path == ("tags", "b")
    assert first[1].path == ("region",)


def test_empty_collections_produce_no_drift():
    assert detect_drift([], []) == []


def test_identity_mismatch_is_not_an_attribute_change():
    findings = detect_drift(
        [bucket("guardrail-a", region="us-east-1")],
        [bucket("guardrail-b", region="us-east-1")],
    )

    assert len(findings) == 2
    change_types = {finding.change_type for finding in findings}
    assert change_types == {ChangeType.RESOURCE_MISSING, ChangeType.RESOURCE_UNEXPECTED}
    assert all(finding.path == () for finding in findings)


def test_duplicate_expected_resources_raise_error():
    with pytest.raises(DuplicateResourceError) as exc_info:
        detect_drift(
            [
                bucket("guardrail-example-data", region="us-east-1"),
                bucket("guardrail-example-data", region="us-west-2"),
            ],
            [],
        )

    assert "aws_s3_bucket" in str(exc_info.value)
    assert "guardrail-example-data" in str(exc_info.value)


def test_duplicate_observed_resources_raise_error():
    with pytest.raises(DuplicateResourceError):
        detect_drift(
            [],
            [
                bucket("guardrail-example-data", region="us-east-1"),
                bucket("guardrail-example-data", region="us-east-1"),
            ],
        )


def test_unique_resources_still_behave_the_same():
    findings = detect_drift(
        [
            bucket("guardrail-a", region="us-east-1"),
            bucket("guardrail-b", region="us-west-2"),
        ],
        [
            bucket("guardrail-a", region="us-east-1"),
            bucket("guardrail-b", region="us-west-1"),
        ],
    )

    assert len(findings) == 1
    assert findings[0].identity == {"bucket": "guardrail-b"}
    assert findings[0].path == ("region",)


FULL_ACCESS_BLOCK = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}


def test_equal_public_access_block_produces_no_drift():
    expected = [bucket("guardrail-example-data", public_access_block=FULL_ACCESS_BLOCK)]
    observed = [bucket("guardrail-example-data", public_access_block=FULL_ACCESS_BLOCK)]

    assert detect_drift(expected, observed) == []


def test_public_access_block_setting_changed():
    findings = detect_drift(
        [bucket("guardrail-example-data", public_access_block=FULL_ACCESS_BLOCK)],
        [
            bucket(
                "guardrail-example-data",
                public_access_block={
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": False,
                    "restrict_public_buckets": True,
                },
            )
        ],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.ATTRIBUTE_CHANGED
    assert finding.path == ("public_access_block", "block_public_policy")
    assert finding.expected is True
    assert finding.observed is False


def test_observed_public_access_block_added_when_expected_absent():
    findings = detect_drift(
        [bucket("guardrail-example-data")],
        [bucket("guardrail-example-data", public_access_block=FULL_ACCESS_BLOCK)],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.ATTRIBUTE_ADDED
    assert finding.path == ("public_access_block",)
    assert finding.expected is ABSENT
    assert finding.observed == FULL_ACCESS_BLOCK


def test_expected_public_access_block_removed_when_observed_absent():
    findings = detect_drift(
        [bucket("guardrail-example-data", public_access_block=FULL_ACCESS_BLOCK)],
        [bucket("guardrail-example-data")],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.change_type is ChangeType.ATTRIBUTE_REMOVED
    assert finding.path == ("public_access_block",)
    assert finding.expected == FULL_ACCESS_BLOCK
    assert finding.observed is ABSENT