import argparse
import json
import sys
from dataclasses import dataclass

from botocore.exceptions import BotoCoreError, ClientError

from guardrail.aws.client import get_s3_client
from guardrail.aws.s3 import S3Collector
from guardrail.config import DEFAULT_STATE_PATH
from guardrail.drift import detect_drift
from guardrail.models import (
    CanonicalResource,
    DriftFinding,
    DuplicateResourceError,
    PolicyViolation,
)
from guardrail.normalize import (
    S3NormalizationError,
    normalize_s3_aws,
    normalize_s3_terraform_resources,
)
from guardrail.output import render_json, render_terminal
from guardrail.policy import evaluate_policies
from guardrail.terraform import TerraformStateError, load_resources

_EXIT_CLEAN = 0
_EXIT_FINDINGS = 1
_EXIT_ERROR = 2


@dataclass(frozen=True)
class ScanResult:
    expected_resources: list[CanonicalResource]
    observed_resources: list[CanonicalResource]
    drift: list[DriftFinding]
    policy_violations: list[PolicyViolation]
    unsupported_resource_types: tuple[str, ...]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="Detect drift and policy violations in AWS infrastructure.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan infrastructure for drift and policy violations.",
    )
    scan_parser.add_argument(
        "--state",
        default=DEFAULT_STATE_PATH,
        metavar="PATH",
        help=f"Path to Terraform state file (default: {DEFAULT_STATE_PATH}).",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args.state, as_json=args.json)

    return _EXIT_ERROR


def build_scan(state_path: str, s3_client) -> ScanResult:
    terraform_resources = load_resources(state_path)
    expected_canonical, unsupported = normalize_s3_terraform_resources(terraform_resources)
    observed_canonical = [normalize_s3_aws(r) for r in S3Collector(s3_client).collect_all()]

    return ScanResult(
        expected_resources=expected_canonical,
        observed_resources=observed_canonical,
        drift=detect_drift(expected_canonical, observed_canonical),
        policy_violations=evaluate_policies(observed_canonical),
        unsupported_resource_types=unsupported,
    )


def run_scan(
    state_path: str,
    s3_client=None,
    *,
    as_json: bool = False,
    client_factory=get_s3_client,
) -> int:
    try:
        if s3_client is None:
            s3_client = client_factory()
        result = build_scan(state_path, s3_client)
    except (
        TerraformStateError,
        S3NormalizationError,
        DuplicateResourceError,
        ClientError,
        BotoCoreError,
    ) as exc:
        print(f"guardrail: error: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    if as_json:
        print(
            json.dumps(
                render_json(
                    expected_count=len(result.expected_resources),
                    observed_count=len(result.observed_resources),
                    drift=result.drift,
                    policy_violations=result.policy_violations,
                    unsupported_resource_types=result.unsupported_resource_types,
                ),
                indent=2,
            )
        )
    else:
        print(
            render_terminal(
                expected_count=len(result.expected_resources),
                observed_count=len(result.observed_resources),
                drift=result.drift,
                policy_violations=result.policy_violations,
                unsupported_resource_types=result.unsupported_resource_types,
            )
        )

    if result.drift or result.policy_violations:
        return _EXIT_FINDINGS
    return _EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())