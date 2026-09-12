from typing import Any

from guardrail.models.canonical import CanonicalResource
from guardrail.models.resource import Resource

_S3_BUCKET_TYPE = "aws_s3_bucket"
_MEANINGFUL_ATTRIBUTES = ("bucket", "region", "tags", "versioning", "encryption")


class S3NormalizationError(Exception):
    """Raised when an S3 resource cannot be normalized."""


def normalize_s3_terraform(resource: Resource) -> CanonicalResource:
    _require_s3_bucket_type(resource)

    bucket = resource.attributes.get("bucket")
    if not bucket:
        raise S3NormalizationError(
            "Terraform aws_s3_bucket is missing the 'bucket' attribute"
        )

    attributes = {
        key: _translate_terraform_attribute(key, resource.attributes[key])
        for key in _MEANINGFUL_ATTRIBUTES
        if key in resource.attributes
    }

    return CanonicalResource(
        resource_type=_S3_BUCKET_TYPE,
        identity={"bucket": bucket},
        attributes=attributes,
        terraform_address=resource.address,
    )


def normalize_s3_aws(resource: Resource) -> CanonicalResource:
    _require_s3_bucket_type(resource)

    if resource.identity is None or "bucket" not in resource.identity:
        raise S3NormalizationError(
            "AWS aws_s3_bucket is missing identity['bucket']"
        )

    attributes = {
        key: value
        for key, value in resource.attributes.items()
        if key in _MEANINGFUL_ATTRIBUTES
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
    if key == "encryption":
        return _translate_encryption(value)
    return value


def _translate_versioning(value: dict[str, Any]) -> dict[str, str]:
    return {
        "status": "Enabled" if value.get("enabled") else "Suspended",
        "mfa_delete": "Enabled" if value.get("mfa_delete") else "Disabled",
    }


def _translate_encryption(value: dict[str, Any]) -> dict[str, str | None]:
    default = value["apply_server_side_encryption_by_default"]
    return {
        "sse_algorithm": default.get("sse_algorithm"),
        "kms_master_key_id": default.get("kms_master_key_id"),
    }