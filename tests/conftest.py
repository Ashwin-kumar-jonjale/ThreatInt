"""Shared test fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatint.config import load_config  # noqa: E402


@pytest.fixture(scope="session")
def config():
    return load_config(str(ROOT / "config" / "config.yaml"))
