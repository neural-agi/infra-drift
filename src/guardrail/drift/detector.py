from collections.abc import Iterable
from typing import Any

from guardrail.models.canonical import CanonicalResource
from guardrail.models.drift import (
    ABSENT,
    ChangeType,
    DriftFinding,
    DuplicateResourceError,
)


def detect_drift(
    expected: Iterable[CanonicalResource],
    observed: Iterable[CanonicalResource],
) -> list[DriftFinding]:
    expected_by_key = _index_by_key(expected, "expected")
    observed_by_key = _index_by_key(observed, "observed")

    findings: list[DriftFinding] = []

    for key in sorted(expected_by_key):
        if key not in observed_by_key:
            findings.append(_unexpected_or_missing(expected_by_key[key], ChangeType.RESOURCE_MISSING))

    for key in sorted(observed_by_key):
        if key not in expected_by_key:
            findings.append(_unexpected_or_missing(observed_by_key[key], ChangeType.RESOURCE_UNEXPECTED))

    for key in sorted(expected_by_key):
        if key in observed_by_key:
            findings.extend(_diff_resource(expected_by_key[key], observed_by_key[key]))

    return sorted(findings, key=_finding_sort_key)


def _resource_key(resource: CanonicalResource) -> tuple[str, tuple[tuple[str, str], ...]]:
    return (resource.resource_type, tuple(sorted(resource.identity.items())))


def _index_by_key(
    resources: Iterable[CanonicalResource], source: str
) -> dict[tuple[str, tuple[tuple[str, str], ...]], CanonicalResource]:
    indexed: dict[tuple[str, tuple[tuple[str, str], ...]], CanonicalResource] = {}

    for resource in resources:
        key = _resource_key(resource)
        if key in indexed:
            raise DuplicateResourceError(
                f"Duplicate {source} resource {resource.resource_type} "
                f"with identity {resource.identity}"
            )
        indexed[key] = resource

    return indexed


def _unexpected_or_missing(
    resource: CanonicalResource, change_type: ChangeType
) -> DriftFinding:
    if change_type is ChangeType.RESOURCE_MISSING:
        return DriftFinding(
            resource_type=resource.resource_type,
            identity=resource.identity,
            change_type=change_type,
            expected=resource,
        )
    return DriftFinding(
        resource_type=resource.resource_type,
        identity=resource.identity,
        change_type=change_type,
        observed=resource,
    )


def _diff_resource(
    expected: CanonicalResource, observed: CanonicalResource
) -> list[DriftFinding]:
    return _diff_attributes(
        expected.attributes,
        observed.attributes,
        prefix=(),
        resource_type=expected.resource_type,
        identity=expected.identity,
    )


def _diff_attributes(
    expected: dict[str, Any],
    observed: dict[str, Any],
    prefix: tuple[str, ...],
    resource_type: str,
    identity: dict[str, str],
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []

    for key in sorted(set(expected) | set(observed)):
        path = prefix + (key,)
        expected_value = expected.get(key, ABSENT)
        observed_value = observed.get(key, ABSENT)

        if isinstance(expected_value, dict) and isinstance(observed_value, dict):
            findings.extend(
                _diff_attributes(expected_value, observed_value, path, resource_type, identity)
            )
        elif expected_value != observed_value:
            findings.append(
                DriftFinding(
                    resource_type=resource_type,
                    identity=identity,
                    change_type=_attribute_change_type(expected_value, observed_value),
                    path=path,
                    expected=expected_value,
                    observed=observed_value,
                )
            )

    return findings


def _attribute_change_type(expected: Any, observed: Any) -> ChangeType:
    if expected is ABSENT:
        return ChangeType.ATTRIBUTE_ADDED
    if observed is ABSENT:
        return ChangeType.ATTRIBUTE_REMOVED
    return ChangeType.ATTRIBUTE_CHANGED


def _finding_sort_key(
    finding: DriftFinding,
) -> tuple[str, tuple[tuple[str, str], ...], str, tuple[str, ...]]:
    return (
        finding.resource_type,
        tuple(sorted(finding.identity.items())),
        finding.change_type.value,
        finding.path,
    )