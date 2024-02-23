"""End-to-end engine tests: default policy across whole fixtures."""

from __future__ import annotations

from collections import Counter

from tfpolicy.engine import build_rules, evaluate
from tfpolicy.models import Plan, Severity
from tfpolicy.policy import load_policy
from tfpolicy.report import has_failures


def test_clean_plan_yields_no_violations(clean_plan: Plan) -> None:
    rules = build_rules(load_policy())
    violations = evaluate(clean_plan, rules)
    assert violations == []
    assert has_failures(violations) is False


def test_violations_plan_fires_expected_rules(violations_plan: Plan) -> None:
    rules = build_rules(load_policy())
    violations = evaluate(violations_plan, rules)

    fired = Counter((v.address, v.rule_id) for v in violations)

    # Exact rule/resource pairs we expect from the default policy.
    assert fired[("aws_s3_bucket.public", "s3_public_access")] == 1
    assert fired[("aws_s3_bucket_public_access_block.public", "s3_public_access")] == 2
    assert fired[("aws_security_group.wide_open", "sg_open_ingress")] == 2
    assert fired[("aws_s3_bucket.public", "required_tags")] == 1
    assert fired[("aws_iam_policy.admin", "iam_wildcard")] == 1
    assert fired[("aws_instance.oversized", "instance_type_allowlist")] == 1

    # No unexpected rule/resource pairs slipped in.
    expected_pairs = {
        ("aws_s3_bucket.public", "s3_public_access"),
        ("aws_s3_bucket_public_access_block.public", "s3_public_access"),
        ("aws_security_group.wide_open", "sg_open_ingress"),
        ("aws_s3_bucket.public", "required_tags"),
        ("aws_iam_policy.admin", "iam_wildcard"),
        ("aws_instance.oversized", "instance_type_allowlist"),
    }
    assert set(fired) == expected_pairs


def test_severities_follow_default_policy(violations_plan: Plan) -> None:
    rules = build_rules(load_policy())
    violations = evaluate(violations_plan, rules)

    by_rule = {v.rule_id: v.severity for v in violations}
    assert by_rule["s3_public_access"] is Severity.FAIL
    assert by_rule["sg_open_ingress"] is Severity.FAIL
    assert by_rule["iam_wildcard"] is Severity.FAIL
    assert by_rule["instance_type_allowlist"] is Severity.FAIL
    # required_tags is a warning by default.
    assert by_rule["required_tags"] is Severity.WARN

    assert has_failures(violations) is True


def test_disabled_rule_is_skipped(violations_plan: Plan) -> None:
    policy = load_policy()
    policy["iam_wildcard"] = policy["iam_wildcard"].__class__(
        enabled=False,
        severity=policy["iam_wildcard"].severity,
        options=policy["iam_wildcard"].options,
    )
    rules = build_rules(policy)
    violations = evaluate(violations_plan, rules)
    assert all(v.rule_id != "iam_wildcard" for v in violations)


def test_warn_only_plan_does_not_fail(violations_plan: Plan) -> None:
    # Keep only the (warn-severity) required_tags rule enabled.
    policy = load_policy()
    for rule_id, settings in list(policy.items()):
        if rule_id != "required_tags":
            policy[rule_id] = settings.__class__(
                enabled=False, severity=settings.severity, options=settings.options
            )
    rules = build_rules(policy)
    violations = evaluate(violations_plan, rules)
    assert violations
    assert all(v.severity is Severity.WARN for v in violations)
    assert has_failures(violations) is False
