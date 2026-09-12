terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {}

# The legacy nested blocks keep versioning and encryption on the single
# aws_s3_bucket resource so GuardRail sees one expected resource in state.
# They are deprecated but still working on the current AWS provider.
resource "aws_s3_bucket" "data" {
  bucket = "guardrail-example-data"

  tags = {
    Environment = "production"
  }

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}