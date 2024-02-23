"""Shared pytest fixtures for the tfpolicy test suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tfpolicy.models import Plan
from tfpolicy.plan import load_plan

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _read_plan(name: str) -> Plan:
    data: dict[str, Any] = json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
    return load_plan(data)


@pytest.fixture
def clean_plan() -> Plan:
    return _read_plan("clean_plan.json")


@pytest.fixture
def violations_plan() -> Plan:
    return _read_plan("violations_plan.json")


@pytest.fixture
def sg_rule_plan() -> Plan:
    return _read_plan("sg_rule_plan.json")
