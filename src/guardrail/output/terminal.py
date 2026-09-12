import json
from typing import Any

from guardrail.models import ABSENT, CanonicalResource, DriftFinding, PolicyViolation


def render_terminal(
    *,
    expected_count: int,
    observed_count: int,
    drift: list[DriftFinding],
    policy_violations: list[PolicyViolation],
    unsupported_resource_types: tuple[str, ...],
) -> str:
    lines = ["GuardRail Scan", ""]
    lines.append("Resources:")
    lines.append(f"  expected: {expected_count}")
    lines.append(f"  observed: {observed_count}")
    if unsupported_resource_types:
        lines.append(
            "  ignoring unsupported resource type(s): "
            + ", ".join(unsupported_resource_types)
        )
    lines.append("")
    lines.append("Drift:")
    if not drift:
        lines.append("  no drift detected")
    else:
        lines.append(f"  {len(drift)} change(s) detected")
        for finding in drift:
            lines.append("")
            lines.append(f"  {_finding_header(finding)}")
            lines.append(f"    type: {finding.change_type.value}")
            if finding.path:
                lines.append(f"    path: {'.'.join(finding.path)}")
            lines.append(f"    expected: {_display_value(finding.expected)}")
            lines.append(f"    observed: {_display_value(finding.observed)}")
    lines.append("")
    lines.append("Policy violations:")
    if not policy_violations:
        lines.append("  no policy violations")
    else:
        lines.append(f"  {len(policy_violations)} violation(s)")
        for violation in policy_violations:
            lines.append("")
            lines.append(f"  {violation.policy.value}")
            lines.append(
                f"    resource: {_resource_header(violation.resource_type, violation.identity)}"
            )
            lines.append(f"    expected: {_display_value(violation.expected)}")
            lines.append(f"    observed: {_display_value(violation.observed)}")
            lines.append(f"    reason: {violation.reason}")
    return "\n".join(lines)


def _finding_header(finding: DriftFinding) -> str:
    resource = _finding_resource(finding)
    if resource is not None and resource.terraform_address:
        return resource.terraform_address
    return _resource_header(finding.resource_type, finding.identity)


def _finding_resource(finding: DriftFinding) -> CanonicalResource | None:
    if isinstance(finding.expected, CanonicalResource):
        return finding.expected
    if isinstance(finding.observed, CanonicalResource):
        return finding.observed
    return None


def _resource_header(resource_type: str, identity: dict[str, str]) -> str:
    parts = ", ".join(f"{key}={value}" for key, value in sorted(identity.items()))
    return f"{resource_type} ({parts})"


def _display_value(value: Any) -> str:
    if value is ABSENT:
        return "<absent>"
    if isinstance(value, CanonicalResource):
        header = _resource_header(value.resource_type, value.identity)
        if value.terraform_address:
            header = f"{header} ({value.terraform_address})"
        return header
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)