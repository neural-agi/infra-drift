from dataclasses import dataclass
from enum import Enum
from typing import Any


class Policy(Enum):
    S3_ENCRYPTION = "s3-encryption"
    S3_VERSIONING = "s3-versioning"
    S3_BLOCK_PUBLIC_ACCESS = "s3-block-public-access"


@dataclass(frozen=True)
class PolicyViolation:
    """A concrete rule whose requirement a resource does not meet.

    expected describes what the rule requires; observed is the canonical
    value seen for the resource. Severity and security impact are concerns
    of a future layer and are deliberately not modeled here.
    """

    resource_type: str
    identity: dict[str, str]
    policy: Policy
    expected: Any
    observed: Any
    reason: str