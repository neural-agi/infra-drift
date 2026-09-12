"""Policy evaluation for GuardRail.

Policies are explicit rules evaluated against CanonicalResource state,
independently of drift detection. Only rules that can be decided from the
canonical state GuardRail actually collects are implemented.

The s3-block-public-access policy checks the bucket-level Block Public
Access configuration only. That is a single security control: a bucket
could still be publicly exposed through bucket policies, ACLs, access
points, or account-level settings, which GuardRail does not determine.
"""

from collections.abc import Iterable

from guardrail.models.canonical import CanonicalResource
from guardrail.models.policy import Policy, PolicyViolation

_S3_BUCKET_TYPE = "aws_s3_bucket"
_PUBLIC_ACCESS_BLOCK_SETTINGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)


def evaluate_policies(resources: Iterable[CanonicalResource]) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []

    for resource in resources:
        if resource.resource_type != _S3_BUCKET_TYPE:
            continue
        violations.extend(_evaluate_s3_policies(resource))

    return sorted(violations, key=_violation_sort_key)


def _evaluate_s3_policies(resource: CanonicalResource) -> list[PolicyViolation]:
    return [
        *encryption_violations(resource),
        *versioning_violations(resource),
        *public_access_block_violations(resource),
    ]


def encryption_violations(resource: CanonicalResource) -> list[PolicyViolation]:
    encryption = resource.attributes.get("encryption", {})
    if encryption:
        return []

    return [
        PolicyViolation(
            resource_type=resource.resource_type,
            identity=resource.identity,
            policy=Policy.S3_ENCRYPTION,
            expected="server-side encryption is configured",
            observed=encryption,
            reason="bucket has no server-side encryption configured",
        )
    ]


def versioning_violations(resource: CanonicalResource) -> list[PolicyViolation]:
    versioning = resource.attributes.get("versioning", {})
    if versioning.get("status") == "Enabled":
        return []

    return [
        PolicyViolation(
            resource_type=resource.resource_type,
            identity=resource.identity,
            policy=Policy.S3_VERSIONING,
            expected={"status": "Enabled"},
            observed=versioning,
            reason="bucket versioning is not enabled",
        )
    ]


def public_access_block_violations(resource: CanonicalResource) -> list[PolicyViolation]:
    access_block = resource.attributes.get("public_access_block", {})

    if all(access_block.get(key) for key in _PUBLIC_ACCESS_BLOCK_SETTINGS):
        return []

    return [
        PolicyViolation(
            resource_type=resource.resource_type,
            identity=resource.identity,
            policy=Policy.S3_BLOCK_PUBLIC_ACCESS,
            expected={
                "block_public_acls": True,
                "ignore_public_acls": True,
                "block_public_policy": True,
                "restrict_public_buckets": True,
            },
            observed=access_block,
            reason="bucket-level S3 Block Public Access is not fully enabled",
        )
    ]


def _violation_sort_key(
    violation: PolicyViolation,
) -> tuple[str, tuple[tuple[str, str], ...], str]:
    return (
        violation.resource_type,
        tuple(sorted(violation.identity.items())),
        violation.policy.value,
    )