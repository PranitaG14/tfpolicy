"""Wire a policy into concrete rules and evaluate a plan against them."""

from __future__ import annotations

from .models import Plan, Violation
from .policy import Policy
from .rules import RULE_REGISTRY, Rule


def build_rules(policy: Policy) -> list[Rule]:
    """Instantiate the enabled, known rules described by ``policy``.

    Unknown rule ids and disabled rules are skipped. Order follows the
    registry so reports are stable regardless of policy-file ordering.
    """
    rules: list[Rule] = []
    for rule_id, rule_cls in RULE_REGISTRY.items():
        settings = policy.get(rule_id)
        if settings is None or not settings.enabled:
            continue
        rules.append(rule_cls(settings.severity, settings.options))
    return rules


def evaluate(plan: Plan, rules: list[Rule]) -> list[Violation]:
    """Run every rule against ``plan`` and collect the violations."""
    violations: list[Violation] = []
    for rule in rules:
        violations.extend(rule.evaluate(plan))
    return violations
