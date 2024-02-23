"""Unit tests for individual policy rules against realistic plan fixtures."""

from __future__ import annotations

from tfpolicy.models import Plan, Severity
from tfpolicy.rules import (
    IamWildcardRule,
    InstanceTypeAllowlistRule,
    RequiredTagsRule,
    S3PublicAccessRule,
    SecurityGroupIngressRule,
)


class TestS3PublicAccess:
    def test_flags_public_acl_and_disabled_access_block(self, violations_plan: Plan) -> None:
        rule = S3PublicAccessRule(Severity.FAIL, {})
        violations = rule.evaluate(violations_plan)
        addresses = {v.address for v in violations}
        # Public ACL bucket + two disabled access-block keys.
        assert "aws_s3_bucket.public" in addresses
        assert "aws_s3_bucket_public_access_block.public" in addresses
        block_msgs = [
            v.message for v in violations if v.address == "aws_s3_bucket_public_access_block.public"
        ]
        assert len(block_msgs) == 2
        assert any("block_public_acls" in m for m in block_msgs)
        assert any("block_public_policy" in m for m in block_msgs)

    def test_clean_plan_has_no_s3_violations(self, clean_plan: Plan) -> None:
        rule = S3PublicAccessRule(Severity.FAIL, {})
        assert rule.evaluate(clean_plan) == []


class TestSecurityGroupIngress:
    OPTIONS = {"sensitive_ports": [22, 3389, 3306, 5432]}

    def test_flags_open_sensitive_ports(self, violations_plan: Plan) -> None:
        rule = SecurityGroupIngressRule(Severity.FAIL, self.OPTIONS)
        violations = rule.evaluate(violations_plan)
        assert {v.address for v in violations} == {"aws_security_group.wide_open"}
        # Two offending ingress rules (22 and 5432) on the same SG.
        assert len(violations) == 2
        messages = " ".join(v.message for v in violations)
        assert "22" in messages
        assert "5432" in messages

    def test_ignores_open_but_non_sensitive_port(self, clean_plan: Plan) -> None:
        # clean plan opens 443 to the world (fine) and 22 only to a private CIDR.
        rule = SecurityGroupIngressRule(Severity.FAIL, self.OPTIONS)
        assert rule.evaluate(clean_plan) == []

    def test_handles_security_group_rule_resource(self, sg_rule_plan: Plan) -> None:
        rule = SecurityGroupIngressRule(Severity.FAIL, self.OPTIONS)
        violations = rule.evaluate(sg_rule_plan)
        # Only the ingress RDP rule fires; egress-all is ignored.
        assert {v.address for v in violations} == {"aws_security_group_rule.rdp"}
        assert "3389" in violations[0].message


class TestRequiredTags:
    OPTIONS = {
        "required": ["Project", "Owner"],
        "taggable_types": ["aws_instance", "aws_s3_bucket", "aws_security_group"],
    }

    def test_flags_only_resource_missing_a_tag(self, violations_plan: Plan) -> None:
        rule = RequiredTagsRule(Severity.WARN, self.OPTIONS)
        violations = rule.evaluate(violations_plan)
        # Only the public bucket is missing Owner; everything else is fully tagged.
        assert {v.address for v in violations} == {"aws_s3_bucket.public"}
        assert "Owner" in violations[0].message
        assert "Project" not in violations[0].message

    def test_clean_plan_fully_tagged(self, clean_plan: Plan) -> None:
        rule = RequiredTagsRule(Severity.WARN, self.OPTIONS)
        assert rule.evaluate(clean_plan) == []


class TestIamWildcard:
    def test_flags_wildcard_admin(self, violations_plan: Plan) -> None:
        rule = IamWildcardRule(Severity.FAIL, {})
        violations = rule.evaluate(violations_plan)
        assert {v.address for v in violations} == {"aws_iam_policy.admin"}

    def test_scoped_policy_is_clean(self, clean_plan: Plan) -> None:
        rule = IamWildcardRule(Severity.FAIL, {})
        assert rule.evaluate(clean_plan) == []

    def test_one_violation_per_policy_even_with_multiple_bad_statements(self) -> None:
        from tfpolicy.models import ResourceChange

        doc = (
            '{"Statement":['
            '{"Effect":"Allow","Action":"*","Resource":"*"},'
            '{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}'
        )
        plan = Plan(
            resources=(
                ResourceChange(
                    address="aws_iam_policy.double",
                    type="aws_iam_policy",
                    name="double",
                    actions=("create",),
                    after={"policy": doc},
                ),
            )
        )
        rule = IamWildcardRule(Severity.FAIL, {})
        assert len(rule.evaluate(plan)) == 1


class TestInstanceTypeAllowlist:
    OPTIONS = {"allowed": ["t3.micro", "t3.small", "t3.medium"]}

    def test_flags_oversized_instance(self, violations_plan: Plan) -> None:
        rule = InstanceTypeAllowlistRule(Severity.FAIL, self.OPTIONS)
        violations = rule.evaluate(violations_plan)
        assert {v.address for v in violations} == {"aws_instance.oversized"}
        assert "m5.24xlarge" in violations[0].message

    def test_allowed_instance_passes(self, clean_plan: Plan) -> None:
        rule = InstanceTypeAllowlistRule(Severity.FAIL, self.OPTIONS)
        assert rule.evaluate(clean_plan) == []
