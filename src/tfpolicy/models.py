"""Core domain types: parsed plan resources, severities, and violations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How seriously to treat a policy violation."""

    FAIL = "fail"
    WARN = "warn"


@dataclass(frozen=True)
class ResourceChange:
    """A single planned resource change (from ``resource_changes[]``).

    ``after`` is the resource's post-apply attribute map, which is what
    policy rules inspect.
    """

    address: str
    type: str
    name: str
    actions: tuple[str, ...]
    after: dict[str, Any]


@dataclass(frozen=True)
class Plan:
    """A parsed Terraform plan reduced to the resource changes we evaluate."""

    resources: tuple[ResourceChange, ...]

    def by_type(self, *types: str) -> list[ResourceChange]:
        """Return resources whose ``type`` matches any of ``types``."""
        wanted = set(types)
        return [r for r in self.resources if r.type in wanted]


@dataclass(frozen=True)
class Violation:
    """A rule firing against a specific resource."""

    rule_id: str
    severity: Severity
    address: str
    resource_type: str
    message: str
