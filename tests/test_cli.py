"""CLI-level tests: output formats and process exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tfpolicy.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES_DIR / "clean_plan.json")
BAD = str(FIXTURES_DIR / "violations_plan.json")


def test_clean_plan_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([CLEAN])
    out = capsys.readouterr().out
    assert code == 0
    assert "Result: PASS" in out


def test_bad_plan_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([BAD])
    out = capsys.readouterr().out
    assert code == 1
    assert "Result: FAIL" in out
    # Grouped, readable output references the offending resources.
    assert "aws_s3_bucket.public" in out
    assert "aws_iam_policy.admin" in out


def test_json_format_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([BAD, "--format", "json"])
    out = capsys.readouterr().out
    assert code == 1

    payload = json.loads(out)
    assert payload["summary"]["result"] == "fail"
    # 1 (acl) + 2 (access block) + 2 (ingress) + 1 (tags) + 1 (iam) + 1 (instance)
    assert payload["summary"]["violations"] == 8
    assert payload["summary"]["fail"] == 7
    assert payload["summary"]["warn"] == 1

    rule_ids = {v["rule_id"] for v in payload["violations"]}
    assert rule_ids == {
        "s3_public_access",
        "sg_open_ingress",
        "required_tags",
        "iam_wildcard",
        "instance_type_allowlist",
    }


def test_missing_plan_file_returns_error_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main([str(FIXTURES_DIR / "does_not_exist.json")])
    err = capsys.readouterr().err
    assert code == 2
    assert "error" in err.lower()


def test_custom_policy_overrides_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A policy that only enables required_tags (a warning) => no FAIL, exit 0.
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "rules:\n"
        "  required_tags:\n"
        "    enabled: true\n"
        "    severity: warn\n"
        "    required: [Project, Owner]\n"
        "    taggable_types: [aws_s3_bucket]\n",
        encoding="utf-8",
    )
    code = main([BAD, "--policy", str(policy)])
    out = capsys.readouterr().out
    assert code == 0
    assert "required_tags" in out
    assert "s3_public_access" not in out
