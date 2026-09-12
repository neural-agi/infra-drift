from typing import Any

from guardrail.models import ABSENT, CanonicalResource, DriftFinding, PolicyViolation


def render_json(
    *,
    expected_count: int,
    observed_count: int,
    drift: list[DriftFinding],
    policy_violations: list[PolicyViolation],
    unsupported_resource_types: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "status": "clean" if not drift and not policy_violations else "findings",
        "expected_resources": expected_count,
        "observed_resources": observed_count,
        "unsupported_resource_types": list(unsupported_resource_types),
        "drift": [_drift_finding_json(finding) for finding in drift],
        "policy_violations": [_policy_violation_json(violation) for violation in policy_violations],
    }


def _drift_finding_json(finding: DriftFinding) -> dict[str, Any]:
    return {
        "resource_type": finding.resource_type,
        "identity": dict(finding.identity),
        "change_type": finding.change_type.value,
        "path": list(finding.path),
        "expected": _json_safe(finding.expected),
        "observed": _json_safe(finding.observed),
    }


def _policy_violation_json(violation: PolicyViolation) -> dict[str, Any]:
    return {
        "resource_type": violation.resource_type,
        "identity": dict(violation.identity),
        "policy": violation.policy.value,
        "expected": _json_safe(violation.expected),
        "observed": _json_safe(violation.observed),
        "reason": violation.reason,
    }


def _json_safe(value: Any) -> Any:
    """Convert internal values into stable JSON-safe equivalents.

    ABSENT is represented as null. CanonicalResource becomes an explicit
    object with its identity and Terraform address. Enum and change-type
    values are already converted to their string value by callers.
    """
    if value is ABSENT:
        return None
    if isinstance(value, CanonicalResource):
        return {
            "resource_type": value.resource_type,
            "identity": dict(value.identity),
            "attributes": _json_safe(value.attributes),
            "terraform_address": value.terraform_address,
        }
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value