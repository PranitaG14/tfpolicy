"""Parse the JSON emitted by ``terraform show -json plan.tfplan`` into a :class:`Plan`."""

from __future__ import annotations

from typing import Any

from .models import Plan, ResourceChange


def load_plan(data: dict[str, Any]) -> Plan:
    """Build a :class:`Plan` from a decoded ``terraform show -json`` document.

    Pure-destroy changes are skipped: their ``after`` state is null, so no
    forward-looking security rule can meaningfully apply to them.
    """
    resource_changes = data.get("resource_changes") or []
    resources: list[ResourceChange] = []
    for rc in resource_changes:
        change = rc.get("change") or {}
        actions = tuple(change.get("actions") or [])
        if actions == ("delete",):
            continue
        after = change.get("after")
        if not isinstance(after, dict):
            after = {}
        resources.append(
            ResourceChange(
                address=str(rc.get("address", "")),
                type=str(rc.get("type", "")),
                name=str(rc.get("name", "")),
                actions=actions,
                after=after,
            )
        )
    return Plan(resources=tuple(resources))
