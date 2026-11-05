"""Shared fixtures: isolated SQLite DB per test session, autoload disabled."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/ on sys.path

import pytest

_TMP = tempfile.mkdtemp(prefix="specter-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ["SPECTER_AUTOLOAD"] = "0"


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:  # startup runs init_db (autoload off)
        yield c


ANALYST = {"Authorization": "Bearer demo-analyst-token"}
ADMIN = {"Authorization": "Bearer demo-admin-token"}
REPO = Path(__file__).resolve().parents[2]
