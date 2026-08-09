"""Command services for create, report-only resume, and report-only deep."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from .contracts import DEFAULT_LIMITS, DomainCode, GitError, InvalidInputError, Limits
from .handoff import Publication, load_handoff, publish_handoff
from .paths import canonical_path, resolve_project_root
from .project_facts import (
    GitFacts,
    GitStatusCounts,
    NamedArtifactFacts,
    collect_git_facts,
    collect_named_artifacts,
    hash_named_artifact,
)
from .redaction import redact_structured
from .sessions import RecoveryLimits, reconstruct


def _collect_git(root: Path, *, limits: Limits) -> GitFacts:
    try:
        return collect_git_facts(root, limits=limits)
    except GitError as error:
        if error.code != DomainCode.GIT_UNAVAILABLE:
            raise
        return GitFacts(
            root=root,
            is_repository=False,
            head=None,
            branch=None,
            detached=False,
            status=GitStatusCounts(),
        )


def _git_dict(facts: GitFacts) -> dict[str, Any]:
    return {
        "is_repository": facts.is_repository,
        "head": facts.head,
        "branch": facts.branch,
        "detached": facts.detached,
        "status": {
            "entries": facts.status.entries,
            "staged": facts.status.staged,
            "unstaged": facts.status.unstaged,
            "untracked": facts.status.untracked,
            "conflicted": facts.status.conflicted,
            "dirty": facts.status.dirty,
        },
    }


def _artifact_anchor(facts: NamedArtifactFacts, root: Path) -> dict[str, Any]:
    return {
        "name": facts.name,
        "path": facts.path.relative_to(root).as_posix(),
        "size": facts.size,
        "mtime_ns": facts.mtime_ns,
        "sha256": facts.sha256,
    }


def _publication_result(publication: Publication) -> tuple[dict[str, Any], tuple[str, ...]]:
    path = str(publication.path)
    result = {
        "ok": True,
        "action": "create",
        "path": path,
        "sha256": publication.sha256,
        "created_local": publication.created_local,
        "created_utc": publication.created_utc,
        "timezone_offset": publication.timezone_offset,
        "redactions": publication.redactions.as_dict(),
        "size": publication.size,
    }
    return result, (path, publication.created_local, publication.created_utc)


def create(
    *,
    invocation_cwd: os.PathLike[str] | str,
    focus: str,
    handoff: Mapping[str, Any],
    named_artifacts: Mapping[str, os.PathLike[str] | str],
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Create one verified handoff from an already bounded request."""

    root = resolve_project_root(invocation_cwd, limits=limits)
    git_facts = _collect_git(root, limits=limits)
    artifacts = collect_named_artifacts(
        named_artifacts, root=root, include_hash=True, limits=limits
    )
    publication = publish_handoff(
        root,
        handoff,
        focus=focus,
        root_mode="git" if git_facts.is_repository else "cwd",
        git=_git_dict(git_facts),
        artifact_anchors=[_artifact_anchor(item, root) for item in artifacts],
        limits=limits,
    )
    return _publication_result(publication)


def _compare_git(saved: Any, current: GitFacts) -> list[dict[str, Any]]:
    now = _git_dict(current)
    if not isinstance(saved, Mapping):
        return [{"kind": "git_metadata_missing", "current": now}]
    differences: list[dict[str, Any]] = []
    for key in ("is_repository", "head", "branch", "detached"):
        if saved.get(key) != now.get(key):
            differences.append(
                {"kind": f"git_{key}_changed", "saved": saved.get(key), "current": now.get(key)}
            )
    if saved.get("status") != now.get("status"):
        differences.append(
            {"kind": "git_status_changed", "saved": saved.get("status"), "current": now.get("status")}
        )
    return differences


def _compare_artifacts(
    anchors: Any, *, root: Path, limits: Limits
) -> list[dict[str, Any]]:
    if not isinstance(anchors, list):
        return [{"kind": "artifact_metadata_missing"}]
    drift: list[dict[str, Any]] = []
    for anchor in anchors:
        if not isinstance(anchor, Mapping):
            drift.append({"kind": "artifact_metadata_invalid"})
            continue
        name = anchor.get("name")
        path = anchor.get("path")
        expected = anchor.get("sha256")
        if not isinstance(name, str) or not isinstance(path, str):
            drift.append({"kind": "artifact_metadata_invalid"})
            continue
        try:
            current = hash_named_artifact(name, path, root=root, limits=limits)
        except Exception:
            drift.append({"kind": "artifact_unavailable", "name": name, "path": path})
            continue
        if current.sha256 != expected:
            drift.append(
                {
                    "kind": "artifact_changed",
                    "name": name,
                    "path": path,
                    "saved_sha256": expected,
                    "current_sha256": current.sha256,
                }
            )
    return drift


def resume(
    *,
    invocation_cwd: os.PathLike[str] | str,
    handoff_path: os.PathLike[str] | str,
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Validate and report one handoff without mutating project state."""

    root = resolve_project_root(invocation_cwd, limits=limits)
    parsed = load_handoff(root, handoff_path, limits=limits)
    current_git = _collect_git(root, limits=limits)
    drift = _compare_git(parsed.metadata.get("git"), current_git)
    drift.extend(
        _compare_artifacts(parsed.metadata.get("artifact_anchors"), root=root, limits=limits)
    )
    report = parsed.report()
    report["current_project"] = {"git": _git_dict(current_git)}
    report["drift"] = drift
    report["status"] = "DRIFTED" if drift else "RESTORED"
    result = {"ok": True, "action": "resume", "report": report}
    return result, ()


def deep(
    *,
    invocation_cwd: os.PathLike[str] | str,
    selector: str,
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Reconstruct bounded session evidence and return a redacted report."""

    if not isinstance(selector, str) or not selector.strip():
        raise InvalidInputError("deep selector must not be empty")
    root = canonical_path(resolve_project_root(invocation_cwd, limits=limits))
    recovery_limits = RecoveryLimits()
    report = reconstruct(selector.strip(), root, limits=recovery_limits)
    redacted = redact_structured(report, limits=limits)
    result = {
        "ok": True,
        "action": "deep",
        "report": redacted.value,
        "redactions": redacted.counts.as_dict(),
    }
    return result, ()
