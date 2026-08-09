"""Static source provenance for Session Continuity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

UPSTREAMS = (
    {
        "name": "mattpocock/skills productivity/handoff",
        "commit": "84fdeffd12f2ee307994d1eb6feb48173b6e0502",
        "url": (
            "https://github.com/mattpocock/skills/tree/"
            "84fdeffd12f2ee307994d1eb6feb48173b6e0502/skills/productivity/handoff"
        ),
        "adapted": "explicit lightweight handoff from the current conversation",
    },
    {
        "name": "softaworks/agent-toolkit session-handoff",
        "commit": "3027f20f3181758385a1bb8c022d4041dfb4de84",
        "url": (
            "https://github.com/softaworks/agent-toolkit/tree/"
            "3027f20f3181758385a1bb8c022d4041dfb4de84/skills/session-handoff"
        ),
        "adapted": "structured handoff lifecycle and current-project reconciliation",
    },
    {
        "name": "hacktivist123/agent-session-resume",
        "commit": "76b025634ddc99b3ee3428fb4464af1c467da291",
        "url": "https://github.com/hacktivist123/agent-session-resume/tree/76b025634ddc99b3ee3428fb4464af1c467da291",
        "adapted": "session discovery, evidence reconstruction, and layered evaluation",
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_files(root: Path) -> Iterable[Path]:
    fixed = (root / "SKILL.md", root / "README.md", root / "DESIGN.md")
    for path in fixed:
        if path.is_file():
            yield path
    for directory in (root / "scripts", root / "src", root / "references"):
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".py", ".md"}:
                yield path


def build_report(root: Path | None = None) -> dict[str, object]:
    project_root = root or Path(__file__).resolve().parents[2]
    files = {
        path.relative_to(project_root).as_posix(): _sha256(path)
        for path in _source_files(project_root)
    }
    return {
        "project": "iuyaa/session-continuity",
        "runtime_network_access": False,
        "upstreams": list(UPSTREAMS),
        "local_sha256": files,
    }


def main() -> int:
    print(json.dumps(build_report(), ensure_ascii=False, sort_keys=True, indent=2))
    return 0
