"""Pytest bootstrap.

Keeps tests runnable without installing the package:
  PYTHONPATH is set to project root for imports like `from core ...`.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Optional: keep MA paths deterministic for tests.
os.environ.setdefault("MA_DATA_DIR", str(ROOT / "runtime"))


import pytest
from app import app
from core.security import reset_rate_limits
from db import create_user
from wallet.user_keys import generate_user_keypair

@pytest.fixture
def client():
    reset_rate_limits()
    try:
        create_user(app.root_path, "neo", "pw123")
    except Exception:
        pass
    try:
        generate_user_keypair(app.root_path, "neo")
    except Exception:
        pass
    with app.test_client() as client:
        yield client
    reset_rate_limits()
