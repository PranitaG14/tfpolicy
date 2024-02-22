"""Load and parse a policy configuration (YAML or JSON) into per-rule settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .models import Severity

_DEFAULT_POLICY_RESOURCE = "default_policy.yaml"


@dataclass(frozen=True)
class RuleSettings:
    """Resolved configuration for a single rule."""

    enabled: bool
    severity: Severity
    options: dict[str, Any] = field(default_factory=dict)


Policy = dict[str, RuleSettings]


def default_policy_text() -> str:
    """Return the bundled default policy file as text."""
    return (
        resources.files("tfpolicy").joinpath(_DEFAULT_POLICY_RESOURCE).read_text(encoding="utf-8")
    )


def parse_policy(raw: dict[str, Any]) -> Policy:
    """Turn a decoded policy document into a mapping of rule id -> settings."""
    rules_raw = raw.get("rules") or {}
    policy: Policy = {}
    for rule_id, cfg in rules_raw.items():
        options = dict(cfg or {})
        enabled = bool(options.pop("enabled", True))
        severity = Severity(str(options.pop("severity", "fail")).lower())
        policy[str(rule_id)] = RuleSettings(enabled=enabled, severity=severity, options=options)
    return policy


def load_policy(path: str | Path | None = None) -> Policy:
    """Load a policy from ``path`` (YAML or JSON), or the bundled default.

    YAML is a strict superset of JSON, so ``yaml.safe_load`` handles both.
    """
    text = Path(path).read_text(encoding="utf-8") if path else default_policy_text()
    raw = yaml.safe_load(text) or {}
    if not isinstance(raw, dict):
        raise ValueError("policy file must decode to a mapping at the top level")
    return parse_policy(raw)
