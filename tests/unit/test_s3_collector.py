import pytest
from botocore.exceptions import ClientError

from guardrail.aws import S3Collector


def client_error(code: str, message: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {}},
        "TestOperation",
    )


class FakeS3Client:
    """Injected stand-in for boto3's s3 client backed by plain dicts."""

    def __init__(
        self,
        *,
        buckets: list[str],
        locations: dict[str, str | None] | None = None,
        tag_sets: dict[str, list[dict[str, str]]] | None = None,
        versioning: dict[str, dict[str, str]] | None = None,
        encryptions: dict[str, dict[str, str]] | None = None,
        public_access_blocks: dict[str, dict[str, bool]] | None = None,
        missing_buckets: set[str] | None = None,
    ) -> None:
        self._buckets = buckets
        self._locations = locations or {}
        self._tag_sets = tag_sets or {}
        self._versioning = versioning or {}
        self._encryptions = encryptions or {}
        self._public_access_blocks = public_access_blocks or {}
        self._missing_buckets = missing_buckets or set()
        self.calls: list[tuple[str, dict | str | None]] = []

    def list_buckets(self) -> dict:
        self.calls.append(("list_buckets", None))
        return {"Buckets": [{"Name": name} for name in self._buckets]}

    def get_bucket_location(self, Bucket: str) -> dict:
        self.calls.append(("get_bucket_location", Bucket))
        if Bucket in self._missing_buckets:
            raise client_error("NoSuchBucket", "The specified bucket does not exist")
        return {"LocationConstraint": self._locations.get(Bucket)}

    def get_bucket_tagging(self, Bucket: str) -> dict:
        self.calls.append(("get_bucket_tagging", Bucket))
        if Bucket not in self._tag_sets:
            raise client_error("NoSuchTagSet", "The TagSet does not exist")
        return {"TagSet": self._tag_sets[Bucket]}

    def get_bucket_versioning(self, Bucket: str) -> dict:
        self.calls.append(("get_bucket_versioning", Bucket))
        return dict(self._versioning.get(Bucket, {}))

    def get_bucket_encryption(self, Bucket: str) -> dict:
        self.calls.append(("get_bucket_encryption", Bucket))
        if Bucket not in self._encryptions:
            raise client_error(
                "ServerSideEncryptionConfigurationNotFoundError",
                "The server side encryption configuration was not found",
            )
        default = self._encryptions[Bucket]
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": default}]
            }
        }

    def get_public_access_block(self, Bucket: str) -> dict:
        self.calls.append(("get_public_access_block", Bucket))
        if Bucket not in self._public_access_blocks:
            raise client_error(
                "NoSuchPublicAccessBlockConfiguration",
                "The public access block configuration was not found",
            )
        return {"PublicAccessBlockConfiguration": self._public_access_blocks[Bucket]}


def test_list_buckets_returns_names():
    client = FakeS3Client(buckets=["guardrail-a", "guardrail-b"])

    assert S3Collector(client).list_buckets() == ["guardrail-a", "guardrail-b"]
    assert client.calls == [("list_buckets", None)]


def test_collect_calls_expected_apis():
    client = FakeS3Client(buckets=["guardrail-data"], locations={"guardrail-data": None})

    S3Collector(client).collect("guardrail-data")

    assert [name for name, _ in client.calls] == [
        "get_bucket_location",
        "get_bucket_tagging",
        "get_bucket_versioning",
        "get_bucket_encryption",
        "get_public_access_block",
    ]
    assert all(bucket == "guardrail-data" for _, bucket in client.calls)


def test_collect_converts_configuration_into_resource():
    client = FakeS3Client(
        buckets=["guardrail-data"],
        locations={"guardrail-data": "us-west-2"},
        tag_sets={
            "guardrail-data": [{"Key": "Environment", "Value": "production"}]
        },
        versioning={"guardrail-data": {"Status": "Enabled", "MFADelete": "Disabled"}},
        encryptions={
            "guardrail-data": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "alias/guardrail",
            }
        },
        public_access_blocks={
            "guardrail-data": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )

    resource = S3Collector(client).collect("guardrail-data")

    assert resource.address is None
    assert resource.resource_type == "aws_s3_bucket"
    assert resource.identity == {"bucket": "guardrail-data"}
    assert resource.attributes == {
        "bucket": "guardrail-data",
        "region": "us-west-2",
        "tags": {"Environment": "production"},
        "versioning": {"status": "Enabled", "mfa_delete": "Disabled"},
        "encryption": {
            "sse_algorithm": "aws:kms",
            "kms_master_key_id": "alias/guardrail",
        },
        "public_access_block": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
    }


def test_region_defaults_to_us_east_1_when_absence_is_reported():
    client = FakeS3Client(buckets=["guardrail-data"], locations={"guardrail-data": None})

    resource = S3Collector(client).collect("guardrail-data")

    assert resource.attributes["region"] == "us-east-1"


def test_region_maps_legacy_eu_constraint_to_eu_west_1():
    client = FakeS3Client(buckets=["guardrail-data"], locations={"guardrail-data": "EU"})

    resource = S3Collector(client).collect("guardrail-data")

    assert resource.attributes["region"] == "eu-west-1"


def test_collect_exposes_provider_identity_not_terraform_address():
    client = FakeS3Client(buckets=["guardrail-data"], locations={"guardrail-data": None})

    resource = S3Collector(client).collect("guardrail-data")

    assert resource.address is None
    assert resource.identity == {"bucket": "guardrail-data"}


def test_absent_optional_configuration_is_represented_as_empty():
    client = FakeS3Client(buckets=["guardrail-bare"], locations={"guardrail-bare": None})

    resource = S3Collector(client).collect("guardrail-bare")

    assert resource.attributes["tags"] == {}
    assert resource.attributes["versioning"] == {}
    assert resource.attributes["encryption"] == {}
    assert resource.attributes["public_access_block"] == {}


def test_public_access_block_settings_are_preserved():
    client = FakeS3Client(
        buckets=["guardrail-data"],
        locations={"guardrail-data": None},
        public_access_blocks={
            "guardrail-data": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            }
        },
    )

    resource = S3Collector(client).collect("guardrail-data")

    assert resource.attributes["public_access_block"] == {
        "block_public_acls": False,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": False,
    }


def test_missing_public_access_block_is_empty_configuration():
    client = FakeS3Client(
        buckets=["guardrail-data"],
        locations={"guardrail-data": None},
        public_access_blocks={},
    )

    resource = S3Collector(client).collect("guardrail-data")

    assert resource.attributes["public_access_block"] == {}


def test_public_access_block_errors_other_than_missing_propagate():
    class FailingClient(FakeS3Client):
        def get_public_access_block(self, Bucket: str) -> dict:
            raise client_error("AccessDenied", "Access Denied")

    client = FailingClient(buckets=["guardrail-data"], locations={"guardrail-data": None})

    with pytest.raises(ClientError) as exc_info:
        S3Collector(client).collect("guardrail-data")

    assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


def test_missing_bucket_propagates_no_such_bucket():
    client = FakeS3Client(
        buckets=["guardrail-data"], missing_buckets={"guardrail-deleted"}
    )

    with pytest.raises(ClientError) as exc_info:
        S3Collector(client).collect("guardrail-deleted")

    assert exc_info.value.response["Error"]["Code"] == "NoSuchBucket"


def test_collect_all_collects_every_bucket():
    client = FakeS3Client(
        buckets=["guardrail-a", "guardrail-b"],
        locations={"guardrail-a": None, "guardrail-b": None},
    )

    resources = S3Collector(client).collect_all()

    assert [resource.identity for resource in resources] == [
        {"bucket": "guardrail-a"},
        {"bucket": "guardrail-b"},
    ]
    assert all(resource.address is None for resource in resources)