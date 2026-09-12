import json
from pathlib import Path
from typing import Any

from guardrail.models.resource import Resource


class TerraformStateError(Exception):
    """Raised when Terraform state cannot be read or parsed."""


def load_state(path: str | Path) -> dict[str, Any]:
    state_path = Path(path)

    try:
        with state_path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError as exc:
        raise TerraformStateError(
            f"Terraform state file not found: {state_path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise TerraformStateError(
            f"Invalid Terraform state JSON: {state_path}"
        ) from exc


def extract_resources(state: dict[str, Any]) -> list[Resource]:
    resources: list[Resource] = []

    for resource in state.get("resources", []):
        resource_type = resource.get("type")
        resource_name = resource.get("name")

        if not resource_type or not resource_name:
            continue

        address = f"{resource_type}.{resource_name}"

        for instance in resource.get("instances", []):
            attributes = instance.get("attributes", {})

            resources.append(
                Resource(
                    address=address,
                    resource_type=resource_type,
                    attributes=attributes,
                )
            )

    return resources


def load_resources(path: str | Path) -> list[Resource]:
    state = load_state(path)
    return extract_resources(state)
