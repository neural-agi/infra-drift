from collections.abc import Iterable
from typing import Any

from guardrail.models.canonical import CanonicalResource
from guardrail.models.resource import Resource

_S3_BUCKET_TYPE = "aws_s3_bucket"
_PUBLIC_ACCESS_BLOCK_TYPE = "aws_s3_bucket_public_access_block"

_CANONICAL_ATTRIBUTE_KEYS = (
    "bucket",
    "region",
    "tags",
    "versioning",
    "encryption",
    "public_access_block",
)
_TERRAFORM_ATTRIBUTE_KEYS = {
    "bucket": "bucket",
    "region": "region",
    "tags": "tags",
    "versioning": "versioning",
    "encryption": "encryption",
    "server_side_encryption_configuration": "encryption",
    "block_public_access": "public_access_block",
}

_PUBLIC_ACCESS_BLOCK_SETTINGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)


class S3NormalizationError(Exception):
    """Raised when an S3 resource cannot be normalized."""


def normalize_s3_terraform(
    resource: Resource, *, public_access_block: dict[str, bool] | None = None
) -> CanonicalResource:
    _require_s3_bucket_type(resource)

    bucket = resource.attributes.get("bucket")
    if not bucket:
        raise S3NormalizationError(
            "Terraform aws_s3_bucket is missing the 'bucket' attribute"
        )

    attributes: dict[str, Any] = {}
    for terraform_key, canonical_key in _TERRAFORM_ATTRIBUTE_KEYS.items():
        if terraform_key in resource.attributes:
            attributes[canonical_key] = _translate_terraform_attribute(
                terraform_key, resource.attributes[terraform_key]
            )
    if public_access_block is not None:
        attributes["public_access_block"] = dict(public_access_block)

    return CanonicalResource(
        resource_type=_S3_BUCKET_TYPE,
        identity={"bucket": bucket},
        attributes=attributes,
        terraform_address=resource.address,
    )


def normalize_s3_terraform_resources(
    resources: Iterable[Resource],
) -> tuple[list[CanonicalResource], tuple[str, ...]]:
    """Normalize Terraform S3 buckets, folding in public access blocks.

    An aws_s3_bucket_public_access_block resource is attached to the
    aws_s3_bucket with the same `bucket` attribute rather than being
    scanned as an independent resource. Other resource types are reported
    as unsupported. Returns (canonical buckets, unsupported types).
    """
    buckets = [r for r in resources if r.resource_type == _S3_BUCKET_TYPE]
    access_blocks = [r for r in resources if r.resource_type == _PUBLIC_ACCESS_BLOCK_TYPE]
    unsupported = tuple(
        sorted(
            {r.resource_type for r in resources}
            - {_S3_BUCKET_TYPE, _PUBLIC_ACCESS_BLOCK_TYPE}
        )
    )

    blocks_by_bucket: dict[str, dict[str, bool]] = {}
    for resource in access_blocks:
        bucket_name = resource.attributes.get("bucket")
        if not bucket_name:
            continue
        if bucket_name in blocks_by_bucket:
            raise S3NormalizationError(
                f"Duplicate {_PUBLIC_ACCESS_BLOCK_TYPE} for bucket {bucket_name}"
            )
        blocks_by_bucket[bucket_name] = {
            key: bool(resource.attributes[key])
            for key in _PUBLIC_ACCESS_BLOCK_SETTINGS
            if key in resource.attributes
        }

    canonical = [
        normalize_s3_terraform(
            bucket,
            public_access_block=blocks_by_bucket.get(bucket.attributes.get("bucket")),
        )
        for bucket in buckets
    ]

    return canonical, unsupported


def normalize_s3_aws(resource: Resource) -> CanonicalResource:
    _require_s3_bucket_type(resource)

    if resource.identity is None or "bucket" not in resource.identity:
        raise S3NormalizationError(
            "AWS aws_s3_bucket is missing identity['bucket']"
        )

    attributes = {
        key: value
        for key, value in resource.attributes.items()
        if key in _CANONICAL_ATTRIBUTE_KEYS
    }

    return CanonicalResource(
        resource_type=_S3_BUCKET_TYPE,
        identity={"bucket": resource.identity["bucket"]},
        attributes=attributes,
        terraform_address=resource.address,
    )


def _require_s3_bucket_type(resource: Resource) -> None:
    if resource.resource_type != _S3_BUCKET_TYPE:
        raise S3NormalizationError(
            f"Expected {_S3_BUCKET_TYPE}, got {resource.resource_type}"
        )


def _translate_terraform_attribute(key: str, value: Any) -> Any:
    if key == "versioning":
        return _translate_versioning(value)
    if key == "encryption" or key == "server_side_encryption_configuration":
        return _translate_encryption(value)
    if key == "block_public_access":
        return _single_block(value)
    return value


def _single_block(value: Any) -> dict[str, Any]:
    """Return the first element of a single repetitive block serialization.

    Terraform serializes nested blocks in state as lists, even when the
    schema allows at most one. Accept both that form and a plain dict.
    """
    if isinstance(value, list):
        if not value:
            return {}
        return _single_block(value[0])
    return value


def _translate_versioning(value: dict[str, Any]) -> dict[str, str]:
    block = _single_block(value)
    return {
        "status": "Enabled" if block.get("enabled") else "Suspended",
        "mfa_delete": "Enabled" if block.get("mfa_delete") else "Disabled",
    }


def _translate_encryption(value: dict[str, Any]) -> dict[str, str | None]:
    block = _single_block(value)

    rule = block.get("rule")
    if isinstance(rule, list):
        if not rule:
            return {}
        rule = rule[0]
    if isinstance(rule, dict):
        block = rule

    default = _single_block(block.get("apply_server_side_encryption_by_default"))
    return {
        "sse_algorithm": default.get("sse_algorithm"),
        "kms_master_key_id": default.get("kms_master_key_id"),
    }