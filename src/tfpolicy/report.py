"""Render violations as a human report or machine-readable JSON."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence

from .models import Severity, Violation


def _counts(violations: Sequence[Violation]) -> tuple[int, int]:
    fail = sum(1 for v in violations if v.severity is Severity.FAIL)
    warn = sum(1 for v in violations if v.severity is Severity.WARN)
    return fail, warn


def has_failures(violations: Sequence[Violation]) -> bool:
    """True if any violation has FAIL severity (drives the process exit code)."""
    return any(v.severity is Severity.FAIL for v in violations)


def render_text(violations: Sequence[Violation]) -> str:
    """Render a readable report grouped by resource address."""
    fail, warn = _counts(violations)
    if not violations:
        return "tfpolicy: no policy violations found.\n\nResult: PASS (0 fail, 0 warn)"

    grouped: dict[str, list[Violation]] = defaultdict(list)
    for violation in violations:
        grouped[violation.address].append(violation)

    lines = [
        f"tfpolicy: {len(violations)} violation(s) " f"across {len(grouped)} resource(s)",
        "",
    ]
    for address in sorted(grouped):
        lines.append(address)
        for violation in sorted(grouped[address], key=lambda v: v.rule_id):
            lines.append(
                f"  [{violation.severity.value.upper()}] "
                f"{violation.rule_id}: {violation.message}"
            )
        lines.append("")

    result = "FAIL" if fail else "PASS"
    lines.append(f"Result: {result} ({fail} fail, {warn} warn)")
    return "\n".join(lines)


def render_json(violations: Sequence[Violation]) -> str:
    """Render violations as indented JSON for machine consumption."""
    fail, warn = _counts(violations)
    payload = {
        "summary": {
            "violations": len(violations),
            "fail": fail,
            "warn": warn,
            "result": "fail" if fail else "pass",
        },
        "violations": [
            {
                "rule_id": v.rule_id,
                "severity": v.severity.value,
                "address": v.address,
                "resource_type": v.resource_type,
                "message": v.message,
            }
            for v in violations
        ],
    }
    return json.dumps(payload, indent=2)
