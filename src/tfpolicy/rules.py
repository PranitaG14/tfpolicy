"""Policy rule implementations.

Every rule is a small, individually-testable class that takes a resolved
severity plus its options and returns the violations it finds in a plan.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from .models import Plan, ResourceChange, Severity, Violation


class Rule(ABC):
    """Base class for all policy rules."""

    rule_id: ClassVar[str]
    description: ClassVar[str]

    def __init__(self, severity: Severity, options: dict[str, Any]) -> None:
        self.severity = severity
        self.options = options

    @abstractmethod
    def evaluate(self, plan: Plan) -> list[Violation]:
        """Return every violation this rule finds in ``plan``."""

    def _violation(self, resource: ResourceChange, message: str) -> Violation:
        return Violation(
            rule_id=self.rule_id,
            severity=self.severity,
            address=resource.address,
            resource_type=resource.type,
            message=message,
        )


def _as_list(value: Any) -> list[Any]:
    """Normalize a scalar-or-list attribute into a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class S3PublicAccessRule(Rule):
    """Flag S3 buckets exposed via a public ACL or a disabled access block."""

    rule_id = "s3_public_access"
    description = "S3 buckets must not be publicly accessible."

    PUBLIC_ACLS: ClassVar[frozenset[str]] = frozenset(
        {"public-read", "public-read-write", "authenticated-read"}
    )
    ACCESS_BLOCK_KEYS: ClassVar[tuple[str, ...]] = (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    )

    def evaluate(self, plan: Plan) -> list[Violation]:
        violations: list[Violation] = []
        for resource in plan.by_type("aws_s3_bucket", "aws_s3_bucket_acl"):
            acl = resource.after.get("acl")
            if isinstance(acl, str) and acl in self.PUBLIC_ACLS:
                violations.append(self._violation(resource, f"S3 bucket ACL is '{acl}' (public)"))
        for resource in plan.by_type("aws_s3_bucket_public_access_block"):
            for key in self.ACCESS_BLOCK_KEYS:
                if resource.after.get(key) is False:
                    violations.append(
                        self._violation(
                            resource,
                            f"public access block '{key}' is disabled (false)",
                        )
                    )
        return violations


class SecurityGroupIngressRule(Rule):
    """Flag ingress open to the world (0.0.0.0/0) on sensitive ports."""

    rule_id = "sg_open_ingress"
    description = "Security groups must not expose sensitive ports to 0.0.0.0/0."

    OPEN_CIDRS: ClassVar[frozenset[str]] = frozenset({"0.0.0.0/0", "::/0"})

    def _sensitive_ports(self) -> set[int]:
        return {int(p) for p in self.options.get("sensitive_ports") or []}

    @staticmethod
    def _open_to_world(cidr_blocks: Any, ipv6_blocks: Any) -> bool:
        candidates = _as_list(cidr_blocks) + _as_list(ipv6_blocks)
        return any(c in SecurityGroupIngressRule.OPEN_CIDRS for c in candidates)

    @staticmethod
    def _matched_ports(from_port: Any, to_port: Any, ports: set[int]) -> set[int]:
        if from_port is None or to_port is None:
            return set()
        try:
            low, high = int(from_port), int(to_port)
        except (TypeError, ValueError):
            return set()
        return {p for p in ports if low <= p <= high}

    def evaluate(self, plan: Plan) -> list[Violation]:
        ports = self._sensitive_ports()
        violations: list[Violation] = []

        for resource in plan.by_type("aws_security_group"):
            for ingress in _as_list(resource.after.get("ingress")):
                if not isinstance(ingress, dict):
                    continue
                if not self._open_to_world(
                    ingress.get("cidr_blocks"), ingress.get("ipv6_cidr_blocks")
                ):
                    continue
                matched = self._matched_ports(
                    ingress.get("from_port"), ingress.get("to_port"), ports
                )
                if matched:
                    violations.append(self._render(resource, matched))

        for resource in plan.by_type("aws_security_group_rule"):
            if resource.after.get("type") != "ingress":
                continue
            if not self._open_to_world(
                resource.after.get("cidr_blocks"),
                resource.after.get("ipv6_cidr_blocks"),
            ):
                continue
            matched = self._matched_ports(
                resource.after.get("from_port"), resource.after.get("to_port"), ports
            )
            if matched:
                violations.append(self._render(resource, matched))

        return violations

    def _render(self, resource: ResourceChange, ports: set[int]) -> Violation:
        listed = ", ".join(str(p) for p in sorted(ports))
        return self._violation(
            resource, f"ingress open to 0.0.0.0/0 on sensitive port(s): {listed}"
        )


class RequiredTagsRule(Rule):
    """Ensure every taggable resource carries the required tag set."""

    rule_id = "required_tags"
    description = "Taggable resources must carry the required tags."

    def evaluate(self, plan: Plan) -> list[Violation]:
        required = [str(t) for t in self.options.get("required") or []]
        taggable = {str(t) for t in self.options.get("taggable_types") or []}
        if not required or not taggable:
            return []

        violations: list[Violation] = []
        for resource in plan.resources:
            if resource.type not in taggable:
                continue
            tags = resource.after.get("tags")
            present = set(tags) if isinstance(tags, dict) else set()
            missing = [key for key in required if key not in present]
            if missing:
                violations.append(
                    self._violation(
                        resource,
                        f"missing required tag(s): {', '.join(missing)}",
                    )
                )
        return violations


class IamWildcardRule(Rule):
    """Flag IAM policies granting Action:'*' on Resource:'*' (wildcard admin)."""

    rule_id = "iam_wildcard"
    description = "IAM policies must not grant wildcard admin (*:*)."

    POLICY_TYPES: ClassVar[tuple[str, ...]] = (
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_group_policy",
        "aws_iam_user_policy",
    )

    @staticmethod
    def _statements(document: Any) -> list[Any]:
        if not isinstance(document, str):
            return []
        try:
            parsed = json.loads(document)
        except (ValueError, TypeError):
            return []
        if not isinstance(parsed, dict):
            return []
        return _as_list(parsed.get("Statement"))

    @staticmethod
    def _is_wildcard_admin(statement: Any) -> bool:
        if not isinstance(statement, dict):
            return False
        if statement.get("Effect") != "Allow":
            return False
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        return "*" in actions and "*" in resources

    def evaluate(self, plan: Plan) -> list[Violation]:
        violations: list[Violation] = []
        for resource in plan.by_type(*self.POLICY_TYPES):
            document = resource.after.get("policy")
            for statement in self._statements(document):
                if self._is_wildcard_admin(statement):
                    violations.append(
                        self._violation(
                            resource,
                            "IAM policy grants Action:'*' on Resource:'*' " "(wildcard admin)",
                        )
                    )
                    break
        return violations


class InstanceTypeAllowlistRule(Rule):
    """Restrict EC2 instance types to a configured allowlist."""

    rule_id = "instance_type_allowlist"
    description = "EC2 instance types must be on the allowlist."

    def evaluate(self, plan: Plan) -> list[Violation]:
        allowed = {str(t) for t in self.options.get("allowed") or []}
        if not allowed:
            return []

        violations: list[Violation] = []
        for resource in plan.by_type("aws_instance"):
            instance_type = resource.after.get("instance_type")
            if isinstance(instance_type, str) and instance_type not in allowed:
                violations.append(
                    self._violation(
                        resource,
                        f"instance_type '{instance_type}' is not in the allowlist",
                    )
                )
        return violations


#: Every rule the engine knows how to build, keyed by policy id.
RULE_REGISTRY: dict[str, type[Rule]] = {
    cls.rule_id: cls
    for cls in (
        S3PublicAccessRule,
        SecurityGroupIngressRule,
        RequiredTagsRule,
        IamWildcardRule,
        InstanceTypeAllowlistRule,
    )
}
