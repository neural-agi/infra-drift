from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CanonicalResource:
    """Source-agnostic view of a cloud resource after normalization.

    resource_type and identity answer "what provider resource is this".
    attributes hold the configuration that is meaningful to compare.
    terraform_address is carried as reporting metadata only and is excluded
    from equality, so the same AWS resource referenced by different
    Terraform addresses still compares equal.
    """

    resource_type: str
    identity: dict[str, str]
    attributes: dict[str, Any]
    terraform_address: str | None = field(default=None, compare=False)