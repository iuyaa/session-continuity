#!/usr/bin/env python3
"""Print pinned upstream and local-source provenance as JSON."""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info < (3, 11):
    raise SystemExit("session-continuity requires Python 3.11+")

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from session_continuity.provenance import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
