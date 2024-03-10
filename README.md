# tfpolicy

**A Terraform plan policy linter, catch public buckets, world-open ports, and wildcard-admin IAM *before* `terraform apply`.**

`tfpolicy` reads the JSON that `terraform show -json` produces from a saved plan and evaluates it against a set of security and governance rules. It prints a readable report grouped by resource and **exits non-zero when any FAIL-severity rule is violated**, so it drops straight into CI as a gate between `plan` and `apply`.

It operates purely on plan JSON, no cloud credentials, no live account, no Terraform binary at evaluation time.

## Why it matters

Most infrastructure incidents are boring misconfigurations that a human reviewer skims past in a 400-line plan diff: an `acl = "public-read"` on the wrong bucket, a security group opened to `0.0.0.0/0` on port 22, an IAM policy that quietly grants `*:*`. `tfpolicy` encodes those checks as version-controlled, testable rules and fails the build the moment one appears in a plan.

## Rules shipped

| Rule id | What it catches | Default severity |
|---|---|---|
| `s3_public_access` | S3 buckets with a public ACL, or a public-access-block with any protection disabled | `fail` |
| `sg_open_ingress` | Security-group ingress open to `0.0.0.0/0` on sensitive ports (22, 3389, 3306, 5432) | `fail` |
| `required_tags` | Taggable resources missing a required tag (default: `Project`, `Owner`) | `warn` |
| `iam_wildcard` | IAM policies granting `Action:"*"` on `Resource:"*"` | `fail` |
| `instance_type_allowlist` | EC2 instance types outside a configured allowlist (catches a fat-fingered huge box) | `fail` |

Every rule's severity, enablement, and options (ports, tag set, instance allowlist) are configurable via a small YAML/JSON policy file. A sensible default is bundled ([`src/tfpolicy/default_policy.yaml`](src/tfpolicy/default_policy.yaml)).

## Install

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Quickstart

Produce plan JSON from a real Terraform project, then lint it:

```bash
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json
uv run tfpolicy plan.json
```

You can also invoke it as a module: `uv run python -m tfpolicy plan.json`.

### Example: linting the bundled "bad" fixture

Running against [`tests/fixtures/violations_plan.json`](tests/fixtures/violations_plan.json) - a plan with a public bucket, a disabled access block, a world-open security group, a wildcard-admin IAM policy, an untagged bucket, and an oversized instance:

```console
$ uv run tfpolicy tests/fixtures/violations_plan.json
tfpolicy: 8 violation(s) across 5 resource(s)

aws_iam_policy.admin
  [FAIL] iam_wildcard: IAM policy grants Action:'*' on Resource:'*' (wildcard admin)

aws_instance.oversized
  [FAIL] instance_type_allowlist: instance_type 'm5.24xlarge' is not in the allowlist

aws_s3_bucket.public
  [WARN] required_tags: missing required tag(s): Owner
  [FAIL] s3_public_access: S3 bucket ACL is 'public-read' (public)

aws_s3_bucket_public_access_block.public
  [FAIL] s3_public_access: public access block 'block_public_acls' is disabled (false)
  [FAIL] s3_public_access: public access block 'block_public_policy' is disabled (false)

aws_security_group.wide_open
  [FAIL] sg_open_ingress: ingress open to 0.0.0.0/0 on sensitive port(s): 22
  [FAIL] sg_open_ingress: ingress open to 0.0.0.0/0 on sensitive port(s): 5432

Result: FAIL (7 fail, 1 warn)

$ echo $?
1
```

The clean fixture passes and exits `0`:

```console
$ uv run tfpolicy tests/fixtures/clean_plan.json
tfpolicy: no policy violations found.

Result: PASS (0 fail, 0 warn)

$ echo $?
0
```

### Machine-readable output

`--format json` emits a structured document (a `summary` block plus a flat `violations` array) for dashboards or further processing:

```console
$ uv run tfpolicy tests/fixtures/violations_plan.json --format json
{
  "summary": {
    "violations": 8,
    "fail": 7,
    "warn": 1,
    "result": "fail"
  },
  "violations": [
    {
      "rule_id": "s3_public_access",
      "severity": "fail",
      "address": "aws_s3_bucket.public",
      "resource_type": "aws_s3_bucket",
      "message": "S3 bucket ACL is 'public-read' (public)"
    }
    // ... 7 more
  ]
}
```

### Custom policy

```bash
uv run tfpolicy plan.json --policy my-policy.yaml
```

A policy file only needs the rules you want to change; for example, to tighten the instance allowlist and downgrade tags to a warning:

```yaml
rules:
  instance_type_allowlist:
    enabled: true
    severity: fail
    allowed: [t3.micro, t3.small]
  required_tags:
    enabled: true
    severity: warn
    required: [Project, Owner, CostCenter]
    taggable_types: [aws_instance, aws_s3_bucket]
```

## Use in CI

Because the process exits `1` on any FAIL violation, it gates a pipeline with no extra glue:

```yaml
- run: terraform show -json plan.tfplan > plan.json
- run: uv run tfpolicy plan.json          # non-zero exit fails the job
```

## Architecture

A small, typed pipeline, each stage is independently testable:

```
plan JSON ──> plan.load_plan ──> Plan (models.py)
policy file ─> policy.load_policy ─> {rule_id: RuleSettings}
                                        │
                        engine.build_rules  (RULE_REGISTRY)
                                        │
                        engine.evaluate(plan, rules) ──> [Violation]
                                        │
                        report.render_text / render_json + has_failures
                                        │
                                   cli.main ──> exit code
```

- **`models.py`** - frozen dataclasses: `ResourceChange`, `Plan`, `Violation`, and the `Severity` enum.
- **`plan.py`** - reduces a `terraform show -json` document to the resource changes worth evaluating (pure destroys are skipped).
- **`rules.py`** - one class per rule, each subclassing `Rule` and returning the violations it finds. A `RULE_REGISTRY` maps policy ids to classes.
- **`policy.py`** - loads YAML/JSON policy into per-rule `RuleSettings` (enabled, severity, options); ships a bundled default.
- **`engine.py`** - instantiates the enabled rules and runs them over a plan.
- **`report.py`** - renders text or JSON and decides the exit code via `has_failures`.
- **`cli.py`** - argparse front end (`tfpolicy` console script + `python -m tfpolicy`).

Adding a rule is: write a `Rule` subclass, add it to `RULE_REGISTRY`, give it a stanza in the default policy.

## Development & testing

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy .
uv run pytest -q
```

The suite tests real behavior against realistic plan fixtures ([`tests/fixtures/`](tests/fixtures/)): it asserts exactly which rules fire on which resources, their severities, the JSON payload counts, and the process exit codes. `mypy` runs in strict mode; `ruff` enforces `E,F,I,UP,B,SIM` at a 100-column line length.

Current status (from `uv run pytest -q`): **22 passed**.

## License

MIT

## Maintainer

Maintained by **Pranita Ashok Ghebad**, Senior Automation Developer, with experience building automation solutions and working with Python, JavaScript, Appian, Flowable, and Camunda.

Contact: [paghebad@gmail.com](mailto:paghebad@gmail.com).