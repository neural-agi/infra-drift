import pytest

from guardrail.models import CanonicalResource, Resource
from guardrail.normalize import (
    S3NormalizationError,
    normalize_s3_aws,
    normalize_s3_terraform,
)


def terraform_bucket(**attributes) -> Resource:
    return Resource(
        address="aws_s3_bucket.data",
        resource_type="aws_s3_bucket",
        attributes=attributes,
    )


def aws_bucket(attributes: dict, *, bucket: str = "guardrail-example-data") -> Resource:
    return Resource(
        address=None,
        resource_type="aws_s3_bucket",
        attributes=attributes,
        identity={"bucket": bucket},
    )


def test_terraform_s3_resource_normalizes_into_canonical_form():
    resource = terraform_bucket(
        bucket="guardrail-example-data",
        tags={"Environment": "production", "Owner": "platform"},
    )

    canonical = normalize_s3_terraform(resource)

    assert isinstance(canonical, CanonicalResource)
    assert canonical.resource_type == "aws_s3_bucket"
    assert canonical.identity == {"bucket": "guardrail-example-data"}
    assert canonical.attributes == {
        "bucket": "guardrail-example-data",
        "tags": {"Environment": "production", "Owner": "platform"},
    }
    assert canonical.terraform_address == "aws_s3_bucket.data"


def test_aws_s3_resource_normalizes_into_canonical_form():
    resource = aws_bucket(
        {
            "bucket": "guardrail-example-data",
            "region": "us-east-1",
            "tags": {"Environment": "production"},
            "versioning": {"status": "Enabled", "mfa_delete": "Disabled"},
            "encryption": {
                "sse_algorithm": "aws:kms",
                "kms_master_key_id": "alias/guardrail",
            },
        }
    )

    canonical = normalize_s3_aws(resource)

    assert isinstance(canonical, CanonicalResource)
    assert canonical.resource_type == "aws_s3_bucket"
    assert canonical.identity == {"bucket": "guardrail-example-data"}
    assert canonical.attributes == {
        "bucket": "guardrail-example-data",
        "region": "us-east-1",
        "tags": {"Environment": "production"},
        "versioning": {"status": "Enabled", "mfa_delete": "Disabled"},
        "encryption": {
            "sse_algorithm": "aws:kms",
            "kms_master_key_id": "alias/guardrail",
        },
    }
    assert canonical.terraform_address is None


def test_terraform_and_aws_of_same_bucket_produce_same_identity():
    terraform = normalize_s3_terraform(terraform_bucket(bucket="guardrail-example-data"))
    aws = normalize_s3_aws(aws_bucket({"bucket": "guardrail-example-data"}))

    assert terraform.identity == {"bucket": "guardrail-example-data"}
    assert terraform.identity == aws.identity


def test_terraform_address_does_not_affect_canonical_equality():
    first = normalize_s3_terraform(
        terraform_bucket(bucket="guardrail-example-data", tags={"Tier": "prod"})
    )
    renamed = normalize_s3_terraform(
        Resource(
            address="aws_s3_bucket.renamed",
            resource_type="aws_s3_bucket",
            attributes={"bucket": "guardrail-example-data", "tags": {"Tier": "prod"}},
        )
    )

    assert first.terraform_address != renamed.terraform_address
    assert first == renamed


def test_tag_ordering_does_not_affect_canonical_equality():
    forward = normalize_s3_terraform(
        terraform_bucket(
            bucket="guardrail-example-data",
            tags={"Environment": "production", "Owner": "platform"},
        )
    )
    reversed_tags = normalize_s3_terraform(
        terraform_bucket(
            bucket="guardrail-example-data",
            tags={"Owner": "platform", "Environment": "production"},
        )
    )

    assert forward == reversed_tags


def test_absent_optional_configuration_is_handled_deterministically():
    first = normalize_s3_aws(
        aws_bucket(
            {
                "bucket": "guardrail-bare",
                "region": "us-east-1",
                "tags": {},
                "versioning": {},
                "encryption": {},
            },
            bucket="guardrail-bare",
        )
    )
    second = normalize_s3_aws(
        aws_bucket(
            {
                "bucket": "guardrail-bare",
                "region": "us-east-1",
                "tags": {},
                "versioning": {},
                "encryption": {},
            },
            bucket="guardrail-bare",
        )
    )

    assert first == second
    assert first.attributes["tags"] == {}
    assert first.attributes["versioning"] == {}
    assert first.attributes["encryption"] == {}


def test_terraform_absent_attributes_are_not_invented():
    canonical = normalize_s3_terraform(terraform_bucket(bucket="guardrail-example-data"))

    assert canonical.attributes == {"bucket": "guardrail-example-data"}


def test_normalization_is_deterministic():
    resource = terraform_bucket(
        bucket="guardrail-example-data",
        tags={"Environment": "production"},
    )

    assert normalize_s3_terraform(resource) == normalize_s3_terraform(resource)


def test_terraform_versioning_block_translates_to_canonical_shape():
    canonical = normalize_s3_terraform(
        terraform_bucket(
            bucket="guardrail-example-data",
            versioning={"enabled": True, "mfa_delete": True},
        )
    )

    assert canonical.attributes["versioning"] == {
        "status": "Enabled",
        "mfa_delete": "Enabled",
    }


def test_terraform_encryption_block_translates_to_canonical_shape():
    canonical = normalize_s3_terraform(
        terraform_bucket(
            bucket="guardrail-example-data",
            encryption={
                "apply_server_side_encryption_by_default": {
                    "sse_algorithm": "aws:kms",
                    "kms_master_key_id": "alias/guardrail",
                }
            },
        )
    )

    assert canonical.attributes["encryption"] == {
        "sse_algorithm": "aws:kms",
        "kms_master_key_id": "alias/guardrail",
    }


def test_terraform_and_aws_reconcile_to_equal_canonical_resource():
    terraform = normalize_s3_terraform(
        Resource(
            address="aws_s3_bucket.data",
            resource_type="aws_s3_bucket",
            attributes={
                "bucket": "guardrail-example-data",
                "region": "us-east-1",
                "tags": {"Environment": "production", "Owner": "platform"},
                "versioning": {"enabled": True, "mfa_delete": False},
                "encryption": {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "aws:kms",
                        "kms_master_key_id": "alias/guardrail",
                    }
                },
            },
        )
    )
    aws = normalize_s3_aws(
        Resource(
            address=None,
            resource_type="aws_s3_bucket",
            identity={"bucket": "guardrail-example-data"},
            attributes={
                "bucket": "guardrail-example-data",
                "region": "us-east-1",
                "tags": {"Owner": "platform", "Environment": "production"},
                "versioning": {"status": "Enabled", "mfa_delete": "Disabled"},
                "encryption": {
                    "sse_algorithm": "aws:kms",
                    "kms_master_key_id": "alias/guardrail",
                },
            },
        )
    )

    assert terraform.identity == aws.identity
    assert terraform == aws


def test_terraform_missing_bucket_identity_fails():
    with pytest.raises(S3NormalizationError):
        normalize_s3_terraform(terraform_bucket(tags={"Environment": "production"}))


def test_aws_missing_bucket_identity_fails():
    with pytest.raises(S3NormalizationError):
        normalize_s3_aws(
            Resource(
                address=None,
                resource_type="aws_s3_bucket",
                attributes={"region": "us-east-1"},
                identity=None,
            )
        )


def test_normalizing_unsupported_resource_type_fails():
    resource = Resource(
        address="aws_iam_user.dev",
        resource_type="aws_iam_user",
        attributes={"name": "dev"},
    )

    with pytest.raises(S3NormalizationError):
        normalize_s3_terraform(resource)