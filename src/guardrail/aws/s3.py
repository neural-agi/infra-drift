from typing import Any

from botocore.exceptions import ClientError

from guardrail.models.resource import Resource

_NO_SUCH_TAG_SETS = "NoSuchTagSet"
_NO_ENCRYPTION_CONFIG = "ServerSideEncryptionConfigurationNotFoundError"
_NO_PUBLIC_ACCESS_BLOCK = "NoSuchPublicAccessBlockConfiguration"


class S3Collector:
    """Collects the configuration state of AWS S3 buckets.

    The client is injected so the collector stays independent of how the
    client is created and remains trivially testable.
    """

    def __init__(self, s3_client: Any) -> None:
        self._client = s3_client

    def list_buckets(self) -> list[str]:
        response = self._client.list_buckets()
        return [bucket["Name"] for bucket in response.get("Buckets", [])]

    def collect(self, bucket_name: str) -> Resource:
        attributes = {
            "bucket": bucket_name,
            "region": self._region(bucket_name),
            "tags": self._tags(bucket_name),
            "versioning": self._versioning(bucket_name),
            "encryption": self._encryption(bucket_name),
            "public_access_block": self._public_access_block(bucket_name),
        }

        return Resource(
            address=None,
            resource_type="aws_s3_bucket",
            attributes=attributes,
            identity={"bucket": bucket_name},
        )

    def collect_all(self) -> list[Resource]:
        return [self.collect(bucket_name) for bucket_name in self.list_buckets()]

    def _region(self, bucket_name: str) -> str:
        response = self._client.get_bucket_location(Bucket=bucket_name)
        location = response.get("LocationConstraint")

        if location is None:
            return "us-east-1"
        if location == "EU":
            return "eu-west-1"
        return location

    def _tags(self, bucket_name: str) -> dict[str, str]:
        try:
            response = self._client.get_bucket_tagging(Bucket=bucket_name)
        except ClientError as exc:
            if _error_code(exc) == _NO_SUCH_TAG_SETS:
                return {}
            raise
        return {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}

    def _versioning(self, bucket_name: str) -> dict[str, str]:
        response = self._client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status")

        if not status:
            return {}

        return {
            "status": status,
            "mfa_delete": response.get("MFADelete", "Disabled"),
        }

    def _encryption(self, bucket_name: str) -> dict[str, str | None]:
        try:
            response = self._client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as exc:
            if _error_code(exc) == _NO_ENCRYPTION_CONFIG:
                return {}
            raise

        rules = response["ServerSideEncryptionConfiguration"]["Rules"]
        default = rules[0]["ApplyServerSideEncryptionByDefault"]

        return {
            "sse_algorithm": default.get("SSEAlgorithm"),
            "kms_master_key_id": default.get("KMSMasterKeyID"),
        }

    def _public_access_block(self, bucket_name: str) -> dict[str, bool]:
        try:
            response = self._client.get_public_access_block(Bucket=bucket_name)
        except ClientError as exc:
            if _error_code(exc) == _NO_PUBLIC_ACCESS_BLOCK:
                return {}
            raise

        config = response["PublicAccessBlockConfiguration"]
        return {
            "block_public_acls": config.get("BlockPublicAcls", False),
            "ignore_public_acls": config.get("IgnorePublicAcls", False),
            "block_public_policy": config.get("BlockPublicPolicy", False),
            "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
        }


def _error_code(exc: ClientError) -> str:
    return exc.response["Error"]["Code"]