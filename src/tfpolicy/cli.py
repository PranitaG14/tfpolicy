"""Command-line entry point for tfpolicy."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .engine import build_rules, evaluate
from .plan import load_plan
from .policy import load_policy
from .report import has_failures, render_json, render_text


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tfpolicy",
        description=(
            "Evaluate a Terraform plan (terraform show -json) against "
            "security and governance policy rules."
        ),
    )
    parser.add_argument(
        "plan",
        help="Path to the plan JSON (output of `terraform show -json plan.tfplan`).",
    )
    parser.add_argument(
        "-p",
        "--policy",
        default=None,
        help="Path to a policy file (YAML or JSON). Defaults to the bundled ruleset.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _load_plan_document(path: str) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("plan file must decode to a JSON object")
    return raw


def main(argv: Sequence[str] | None = None) -> int:
    """Run the linter. Returns 0 when no FAIL violations exist, else 1."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        plan_document = _load_plan_document(args.plan)
        policy = load_policy(args.policy)
    except (OSError, ValueError) as exc:
        print(f"tfpolicy: error: {exc}", file=sys.stderr)
        return 2

    plan = load_plan(plan_document)
    rules = build_rules(policy)
    violations = evaluate(plan, rules)

    output = render_json(violations) if args.format == "json" else render_text(violations)
    print(output)

    return 1 if has_failures(violations) else 0


if __name__ == "__main__":
    raise SystemExit(main())
