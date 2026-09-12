import boto3
from typing import Any


def get_s3_client() -> Any:
    return boto3.client("s3")