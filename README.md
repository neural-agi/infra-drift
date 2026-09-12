# GuardRail

GuardRail detects drift between the infrastructure Terraform expects and
what AWS actually has, and evaluates explicit security policies against the
observed state. It focuses on what it can decide from real data: no
hypothetical inference, no partial signals presented as facts.

Supported resource: `aws_s3_bucket`. Other resource types in the Terraform
state are reported as unsupported and skipped.

## Concepts

- **Expected state**: the canonical S3 bucket configuration derived from a
  Terraform state file (e.g. `terraform.tfstate`).
- **Observed state**: the same canonical representation collected live from
  AWS via the S3 API.
- **Drift**: any difference between expected and observed state.
- **Policy violation**: a rule that is violated by the observed state,
  regardless of what Terraform says.

The two are reported separately: drift tells you your infrastructure
changed; policy violations tell you it is not configured as required.

## S3 policies

GuardRail evaluates three policies against observed buckets:

| Policy | Canonical attribute | Passes when |
| --- | --- | --- |
| `s3-encryption` | `encryption` | server-side encryption is configured |
| `s3-versioning` | `versioning` | versioning is `Enabled` |
| `s3-block-public-access` | `public_access_block` | all four bucket-level Block Public Access settings are enabled |

The `s3-block-public-access` policy covers the bucket-level Block Public
Access control only. It is one security control: a bucket can still be
exposed through bucket policies, ACLs, access points, or account-level
settings, which GuardRail does not determine.

## Offline scan

You need a local Terraform state file, plus AWS credentials for reading
bucket configuration.

```sh
guardrail scan --state terraform.tfstate          # human-readable
guardrail scan --state terraform.tfstate --json   # machine-readable
```

Exit codes: `0` clean, `1` drift or policy violations found, `2` error.

Canonical state notes:

- The Terraform fields `encryption` /
  `server_side_encryption_configuration` and
  `block_public_access` (or the standalone
  `aws_s3_bucket_public_access_block` resource) all map to the same
  canonical attributes, so legacy and current provider serializations
  reconcile.
- In JSON output, absent values are `null`.

## Real AWS example

```sh
cd examples/basic
terraform init
terraform apply            # creates guardrail-example-data
guardrail scan             # reads terraform.tfstate by default
```

`terraform apply` creates the example bucket
(`guardrail-example-data`) with versioning, AES256 server-side
encryption, the expected tag, and all four bucket-level Block Public
Access settings. The bucket reflects the expected state, so the scan
reports no drift and no policy violations. The human operator is
responsible for cleaning up the example bucket later (e.g. with
`terraform destroy`).

Terraform writes the state locally as `terraform.tfstate` on apply;
`guardrail scan` reads it by default, so no manual state export is
needed.

Making a live change (e.g. unblocking public access) and re-running the
scan should report drift and a `s3-block-public-access` policy violation on
the next run.

## Live validation

An opt-in, read-only test validates the real AWS pipeline against a
single dedicated bucket. It is skipped by default; enable it explicitly:

```sh
GUARDRAIL_LIVE_AWS=1 \
GUARDRAIL_TEST_BUCKET=<dedicated-bucket-name> \
GUARDRAIL_TEST_REGION=<bucket-region> \
.venv/bin/python -m pytest tests/integration/test_live_aws.py -q
```

Requirements and behavior:

- The test only reads AWS state; GuardRail never creates, modifies, or
  deletes infrastructure.
- It requires AWS credentials (standard SDK credential resolution).
- The bucket named by `GUARDRAIL_TEST_BUCKET` must already exist and
  match the expected configuration (versioning enabled, AES256
  encryption, tag `Environment=production`, and all four Block Public
  Access settings enabled); otherwise the scan reports the difference.
- `GUARDRAIL_TEST_REGION` is optional and defaults to `us-east-1`.