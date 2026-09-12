import json
from pathlib import Path

from botocore.exceptions import ClientError, NoCredentialsError

from guardrail.cli import build_scan, run_scan

FIXTURES = Path(__file__).parents[1] / "fixtures" / "terraform"
CLEAN_STATE = FIXTURES / "scan-clean.tfstate.json"
DRIFT_STATE = FIXTURES / "scan-drift.tfstate.json"
UNSUPPORTED_STATE = FIXTURES / "scan-with-unsupported.tfstate.json"


def client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "simulated failure"}, "ResponseMetadata": {}},
        "TestOperation",
    )


class FakeS3Client:
    def __init__(
        self,
        *,
        buckets: list[str],
        locations: dict[str, str | None] | None = None,
        tag_sets: dict[str, list[dict[str, str]]] | None = None,
        versioning: dict[str, dict[str, str]] | None = None,
        encryptions: dict[str, dict[str, str]] | None = None,
        public_access_blocks: dict[str, dict[str, bool]] | None = None,
        list_error: Exception | None = None,
    ) -> None:
        self._buckets = buckets
        self._locations = locations or {}
        self._tag_sets = tag_sets or {}
        self._versioning = versioning or {}
        self._encryptions = encryptions or {}
        self._public_access_blocks = public_access_blocks or {}
        self._list_error = list_error

    def list_buckets(self) -> dict:
        if self._list_error is not None:
            raise self._list_error
        return {"Buckets": [{"Name": name} for name in self._buckets]}

    def get_bucket_location(self, Bucket: str) -> dict:
        return {"LocationConstraint": self._locations.get(Bucket)}

    def get_bucket_tagging(self, Bucket: str) -> dict:
        if Bucket not in self._tag_sets:
            raise client_error("NoSuchTagSet")
        return {"TagSet": self._tag_sets[Bucket]}

    def get_bucket_versioning(self, Bucket: str) -> dict:
        return dict(self._versioning.get(Bucket, {}))

    def get_bucket_encryption(self, Bucket: str) -> dict:
        if Bucket not in self._encryptions:
            raise client_error("ServerSideEncryptionConfigurationNotFoundError")
        default = self._encryptions[Bucket]
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": default}]
            }
        }

    def get_public_access_block(self, Bucket: str) -> dict:
        if Bucket not in self._public_access_blocks:
            raise client_error("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self._public_access_blocks[Bucket]}


def clean_client(**overrides) -> FakeS3Client:
    options = {
        "buckets": ["guardrail-example-data"],
        "locations": {"guardrail-example-data": None},
        "tag_sets": {"guardrail-example-data": [{"Key": "Environment", "Value": "production"}]},
        "versioning": {"guardrail-example-data": {"Status": "Enabled", "MFADelete": "Disabled"}},
        "encryptions": {
            "guardrail-example-data": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "alias/guardrail",
            }
        },
        "public_access_blocks": {
            "guardrail-example-data": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    }
    options.update(overrides)
    return FakeS3Client(**options)


def test_clean_scan_exits_zero(capsys):
    code = run_scan(CLEAN_STATE, clean_client())

    assert code == 0


def test_drift_found_exits_one(capsys):
    code = run_scan(DRIFT_STATE, clean_client())

    assert code == 1


def test_policy_violation_found_exits_one(capsys):
    code = run_scan(CLEAN_STATE, clean_client(encryptions={}))

    assert code == 1


def test_drift_and_policy_violation_exits_one(capsys):
    code = run_scan(DRIFT_STATE, clean_client(encryptions={}))

    assert code == 1


def test_drifted_public_access_block_exits_one(capsys):
    code = run_scan(
        CLEAN_STATE,
        clean_client(
            public_access_blocks={
                "guardrail-example-data": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": True,
                }
            }
        ),
    )

    assert code == 1


def test_missing_public_access_block_exits_one(capsys):
    code = run_scan(CLEAN_STATE, clean_client(public_access_blocks={}))

    assert code == 1


def test_json_reports_drifted_public_access_block(capsys):
    run_scan(
        CLEAN_STATE,
        clean_client(
            public_access_blocks={
                "guardrail-example-data": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": True,
                }
            }
        ),
        as_json=True,
    )

    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "findings"
    finding = payload["drift"][0]
    assert finding["path"] == ["public_access_block", "block_public_policy"]
    violation = payload["policy_violations"][0]
    assert violation["policy"] == "s3-block-public-access"


def test_json_reports_missing_public_access_block(capsys):
    run_scan(CLEAN_STATE, clean_client(public_access_blocks={}), as_json=True)

    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "findings"
    drift_paths = [finding["path"][0] for finding in payload["drift"]]
    assert drift_paths == ["public_access_block"] * 4
    violation = payload["policy_violations"][0]
    assert violation["policy"] == "s3-block-public-access"
    assert violation["observed"] == {}


def test_human_public_access_block_violation_is_clear(capsys):
    run_scan(CLEAN_STATE, clean_client(public_access_blocks={}))

    out = capsys.readouterr().out
    assert "s3-block-public-access" in out
    assert "not fully enabled" in out


def test_missing_terraform_state_exits_two(capsys):
    code = run_scan(FIXTURES / "does-not-exist.tfstate.json", clean_client())

    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_invalid_terraform_state_exits_two(tmp_path, capsys):
    bad_state = tmp_path / "bad.tfstate"
    bad_state.write_text("this is not json", encoding="utf-8")

    code = run_scan(bad_state, clean_client())

    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_aws_api_failure_exits_two(capsys):
    client = clean_client(list_error=client_error("AccessDenied"))

    code = run_scan(CLEAN_STATE, client)

    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_aws_credential_failure_exits_two(capsys):
    client = clean_client(list_error=NoCredentialsError())

    code = run_scan(CLEAN_STATE, client)

    assert code == 2


def test_json_output_is_valid_json(capsys):
    code = run_scan(CLEAN_STATE, clean_client(), as_json=True)

    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["status"] == "clean"
    assert payload["expected_resources"] == 1
    assert payload["observed_resources"] == 1


def test_json_represents_drift_findings(capsys):
    run_scan(DRIFT_STATE, clean_client(), as_json=True)

    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "findings"
    assert len(payload["drift"]) == 1
    finding = payload["drift"][0]
    assert finding["resource_type"] == "aws_s3_bucket"
    assert finding["identity"] == {"bucket": "guardrail-example-data"}
    assert finding["change_type"] == "attribute_changed"
    assert finding["path"] == ["region"]
    assert finding["expected"] == "eu-west-1"
    assert finding["observed"] == "us-east-1"


def test_json_represents_policy_violations(capsys):
    run_scan(CLEAN_STATE, clean_client(encryptions={}), as_json=True)

    payload = json.loads(capsys.readouterr().out)

    assert len(payload["policy_violations"]) == 1
    violation = payload["policy_violations"][0]
    assert violation["policy"] == "s3-encryption"
    assert violation["identity"] == {"bucket": "guardrail-example-data"}
    assert violation["observed"] == {}


def test_json_has_no_internal_sentinel_leak(capsys):
    run_scan(CLEAN_STATE, clean_client(buckets=[]), as_json=True)

    out = capsys.readouterr().out
    assert "ABSENT" not in out

    payload = json.loads(out)
    finding = payload["drift"][0]
    assert finding["change_type"] == "resource_missing"
    assert finding["identity"] == {"bucket": "guardrail-example-data"}
    assert finding["expected"]["identity"] == {"bucket": "guardrail-example-data"}
    assert finding["expected"]["terraform_address"] == "aws_s3_bucket.data"
    assert finding["observed"] is None


def test_unsupported_resources_are_handled_deterministically(capsys):
    run_scan(UNSUPPORTED_STATE, clean_client(), as_json=True)
    first = capsys.readouterr().out
    run_scan(UNSUPPORTED_STATE, clean_client(), as_json=True)
    second = capsys.readouterr().out

    assert first == second
    payload = json.loads(first)
    assert payload["unsupported_resource_types"] == ["aws_iam_user"]
    assert payload["status"] == "clean"


def test_clean_human_output_is_readable(capsys):
    run_scan(CLEAN_STATE, clean_client())

    out = capsys.readouterr().out
    assert "GuardRail Scan" in out
    assert "expected: 1" in out
    assert "observed: 1" in out
    assert "no drift detected" in out
    assert "no policy violations" in out


def test_human_drift_output_shows_meaningful_values(capsys):
    run_scan(DRIFT_STATE, clean_client())

    out = capsys.readouterr().out
    assert "region" in out
    assert "eu-west-1" in out
    assert "us-east-1" in out
    assert "attribute_changed" in out


def test_human_policy_output_is_clear(capsys):
    run_scan(CLEAN_STATE, clean_client(encryptions={}))

    out = capsys.readouterr().out
    assert "s3-encryption" in out
    assert "guardrail" in out


def test_drift_and_policy_results_remain_separate(capsys):
    run_scan(DRIFT_STATE, clean_client(encryptions={}))

    out = capsys.readouterr().out
    assert "Drift:" in out
    assert "Policy violations:" in out

    run_scan(DRIFT_STATE, clean_client(encryptions={}), as_json=True)
    payload = json.loads(capsys.readouterr().out)
    assert "drift" in payload
    assert "policy_violations" in payload


def test_build_scan_returns_structured_result():
    result = build_scan(CLEAN_STATE, clean_client())

    assert len(result.expected_resources) == 1
    assert len(result.observed_resources) == 1
    assert result.drift == []
    assert result.policy_violations == []
    assert result.unsupported_resource_types == ()