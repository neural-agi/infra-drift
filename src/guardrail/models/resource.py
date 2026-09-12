from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Resource:
    address: str | None
    resource_type: str
    attributes: dict[str, Any]
    identity: dict[str, str] | None = None
