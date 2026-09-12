from pathlib import Path

from guardrail.terraform.state import load_resources


FIXTURE = Path(__file__).parents[1] / "fixtures" / "terraform" / "basic.tfstate.json"


def test_load_resources():
    resources = load_resources(FIXTURE)

    assert len(resources) == 1

    resource = resources[0]

    assert resource.address == "aws_s3_bucket.data"
    assert resource.resource_type == "aws_s3_bucket"
    assert resource.attributes["bucket"] == "guardrail-example-data"
    assert resource.attributes["tags"]["Environment"] == "production"
