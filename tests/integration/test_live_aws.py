"""Opt-in live AWS validation.

Ordinary test runs skip these tests. To exercise the real AWS pipeline
against ONE dedicated bucket, set:

    GUARDRAIL_LIVE_AWS=1
    GUARDRAIL_TEST_BUCKET=<dedicated bucket name>
    GUARDRAIL_TEST_REGION=<bucket region>   (default: us-east-1)

The tests only read AWS state. They never create, modify, or delete
infrastructure.

The expected (Terraform) state is built independently from documented
constants, not derived from what AWS currently reports, so this is a true
comparison: if the bucket drifts from the expected configuration the scan
must report it.
"""

import json
import os
from pathlib import Path

import pytest

from guardrail.aws.client import get_s3_client
from guardrail.aws.s3 import S3Collector
from guardrail.cli import build_scan, run_scan

LIVE_AWS_ENV = "GUARDRAIL_LIVE_AWS"
TEST_BUCKET_ENV = "GUARDRAIL_TEST_BUCKET"
TEST_REGION_ENV = "GUARDRAIL_TEST_REGION"
DEFAULT_REGION = "us-east-1"

EXPECTED_VERSIONING = {"status": "Enabled", "mfa_delete": "Disabled"}
EXPECTED_TAGS = {"Environment": "production"}
EXPECTED_SSE_ALGORITHM = "AES256"
EXPECTED_PUBLIC_ACCESS_BLOCK = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}


def _live_config() -> tuple[str, str]:
    if os.environ.get(LIVE_AWS_ENV) != "1":
        pytest.skip(f"set {LIVE_AWS_ENV}=1 to run live AWS validation")

    bucket = os.environ.get(TEST_BUCKET_ENV)
    if not bucket:
        raise RuntimeError(
            f"{LIVE_AWS_ENV}=1 requires {TEST_BUCKET_ENV} "
            "set to the dedicated test bucket name"
        )
    region = os.environ.get(TEST_REGION_ENV, DEFAULT_REGION)
    return bucket, region


def _write_expectation(tmp_path: Path, bucket: str, region: str) -> Path:
    state = {
        "version": 4,
        "terraform_version": "1.9.0",
        "resources": [
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "data",
                "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                "instances": [
                    {
                        "schema_version": 0,
                        "attributes": {
                            "bucket": bucket,
                            "region": region,
                            "tags": {"Environment": "production"},
                            "versioning": [{"enabled": True, "mfa_delete": False}],
                            "server_side_encryption_configuration": [
                                {
                                    "rule": [
                                        {
                                            "apply_server_side_encryption_by_default": {
                                                "sse_algorithm": "AES256",
                                            }
                                        }
                                    ]
                                }
                            ],
                        },
                    }
                ],
            },
            {
                "mode": "managed",
                "type": "aws_s3_bucket_public_access_block",
                "name": "data",
                "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                "instances": [
                    {
                        "schema_version": 0,
                        "attributes": {
                            "bucket": bucket,
                            "block_public_acls": True,
                            "block_public_policy": True,
                            "ignore_public_acls": True,
                            "restrict_public_buckets": True,
                        },
                    }
                ],
            },
        ],
    }
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    return state_path


def _assert_canonical_matches_expected(canonical) -> None:
    assert canonical.identity == {"bucket": canonical.attributes["bucket"]}
    attributes = canonical.attributes
    assert attributes["region"] == os.environ.get(TEST_REGION_ENV, DEFAULT_REGION)
    assert attributes["tags"] == EXPECTED_TAGS
    assert attributes["versioning"] == EXPECTED_VERSIONING
    assert attributes["encryption"]["sse_algorithm"] == EXPECTED_SSE_ALGORITHM
    assert attributes["public_access_block"] == EXPECTED_PUBLIC_ACCESS_BLOCK


def test_live_scan_collects_and_matches_dedicated_bucket(tmp_path, capsys):
    bucket, region = _live_config()

    client = get_s3_client()
    collector = S3Collector(client)

    assert bucket in collector.list_buckets(), f"{bucket!r} not found in the AWS account"

    observed = collector.collect(bucket)
    _assert_canonical_matches_expected(observed)

    state_path = _write_expectation(tmp_path, bucket, region)
    result = build_scan(state_path, client)
    assert len(result.observed_resources) == 1
    assert result.observed_resources[0].identity == {"bucket": bucket}

    code = run_scan(state_path, client, as_json=True)
    payload = json.loads(capsys.readouterr().out)

    assert result.drift == []
    assert result.policy_violations == []
    assert code == 0
    assert payload["status"] == "clean"
    assert payload["drift"] == []
    assert payload["policy_violations"] == []
    assert payload["observed_resources"] == 1
    assert payload["expected_resources"] == 1