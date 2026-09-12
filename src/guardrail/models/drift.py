from dataclasses import dataclass
from enum import Enum
from typing import Any


class _Absent:
    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = _Absent()


class ChangeType(Enum):
    RESOURCE_MISSING = "resource_missing"
    RESOURCE_UNEXPECTED = "resource_unexpected"
    ATTRIBUTE_ADDED = "attribute_added"
    ATTRIBUTE_REMOVED = "attribute_removed"
    ATTRIBUTE_CHANGED = "attribute_changed"


class DuplicateResourceError(Exception):
    """Raised when multiple canonical resources share the same identity."""


@dataclass(frozen=True)
class DriftFinding:
    """A factual difference between expected and observed infrastructure state.

    DriftFinding describes what *changed* at the infrastructure level.
    Severity, security meaning, and policy violations are concerns of the
    downstream policy layer, not of the drift engine that produces this.
    """

    resource_type: str
    identity: dict[str, str]
    change_type: ChangeType
    path: tuple[str, ...] = ()
    expected: Any = ABSENT
    observed: Any = ABSENT