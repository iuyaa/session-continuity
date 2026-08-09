"""Command services for create, report-only resume, and report-only deep."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    DEFAULT_LIMITS,
    DomainCode,
    DomainError,
    GitError,
    InvalidInputError,
    Limits,
)
from .handoff import Publication, load_handoff, publish_handoff
from .paths import canonical_path, resolve_project_root
from .project_facts import (
    GitFacts,
    GitStatusCounts,
    NamedArtifactFacts,
    collect_git_facts,
    hash_named_artifact,
)
from .redaction import redact_output, redact_structured
from .sessions import RecoveryLimits, reconstruct


@dataclass(frozen=True, slots=True)
class _GitProbe:
    facts: GitFacts
    state: str


def _collect_git_probe(root: Path, *, limits: Limits) -> _GitProbe:
    try:
        facts = collect_git_facts(root, limits=limits)
    except GitError as error:
        if error.code != DomainCode.GIT_UNAVAILABLE:
            raise
        facts = GitFacts(
            root=root,
            is_repository=False,
            head=None,
            branch=None,
            detached=False,
            status=GitStatusCounts(),
        )
        return _GitProbe(facts=facts, state="unavailable")
    state = "checked_repository" if facts.is_repository else "checked_non_repository"
    return _GitProbe(facts=facts, state=state)


def _collect_git(root: Path, *, limits: Limits) -> GitFacts:
    return _collect_git_probe(root, limits=limits).facts


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


def _optional_artifact_anchors(
    artifacts: Mapping[str, os.PathLike[str] | str],
    *,
    root: Path,
    limits: Limits,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    requested = len(artifacts)
    items = sorted(artifacts.items(), key=lambda item: str(item[0]))[
        : limits.max_artifacts
    ]
    anchors: list[dict[str, Any]] = []
    skipped = requested - len(items)
    for name, path in items:
        try:
            facts = hash_named_artifact(name, path, root=root, limits=limits)
            anchor = _artifact_anchor(facts, root)
            clean_path = redact_output(anchor["path"], limits=limits).value
            if clean_path != anchor["path"]:
                skipped += 1
                continue
            anchors.append(anchor)
        except (DomainError, OSError, ValueError):
            skipped += 1
    return anchors, {
        "requested": requested,
        "anchored": len(anchors),
        "skipped": skipped,
    }


def _publication_result(publication: Publication) -> tuple[dict[str, Any], tuple[str, ...]]:
    path = str(publication.path)
    result = {
        "ok": True,
        "action": "create",
        "path": path,
        "sha256": publication.sha256,
        "body_sha256": publication.sha256,
        "file_sha256": publication.file_sha256,
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
    anchors, artifact_summary = _optional_artifact_anchors(
        named_artifacts, root=root, limits=limits
    )
    publication = publish_handoff(
        root,
        handoff,
        focus=focus,
        root_mode="git" if git_facts.is_repository else "cwd",
        git=_git_dict(git_facts),
        artifact_anchors=anchors,
        limits=limits,
    )
    result, allowed_literals = _publication_result(publication)
    result["named_artifacts"] = artifact_summary
    return result, allowed_literals


def _compare_git(saved: Any, current: GitFacts) -> list[dict[str, Any]]:
    now = _git_dict(current)
    if not isinstance(saved, Mapping):
        return [{"kind": "git_metadata_missing", "current": now}]
    differences: list[dict[str, Any]] = []
    for key in ("is_repository", "head", "branch", "detached"):
        if key in saved and saved.get(key) != now.get(key):
            differences.append(
                {"kind": f"git_{key}_changed", "saved": saved.get(key), "current": now.get(key)}
            )
    if "status" in saved and saved.get("status") != now.get("status"):
        differences.append(
            {"kind": "git_status_changed", "saved": saved.get("status"), "current": now.get("status")}
        )
    return differences


def _saved_git_scope(saved: Any) -> tuple[str, list[str], list[str]]:
    expected = ("is_repository", "head", "branch", "detached", "status")
    if not isinstance(saved, Mapping):
        return "metadata_missing", [], list(expected)
    saved_fields = [key for key in expected if key in saved]
    missing_saved_fields = [key for key in expected if key not in saved]
    saved_probe = (
        "checked_repository"
        if saved.get("is_repository") is True
        else "not_recorded_by_schema_v1"
    )
    return saved_probe, saved_fields, missing_saved_fields


def _git_comparison(
    current_probe: str, saved_probe: str, missing_saved_fields: list[str]
) -> str:
    if current_probe == "unavailable":
        return "not_checked_current_unavailable"
    if saved_probe == "metadata_missing":
        return "saved_metadata_missing"
    if missing_saved_fields:
        return "limited_by_saved_v1_fields"
    if saved_probe == "not_recorded_by_schema_v1":
        return "limited_by_saved_v1_availability"
    return "checked_against_stored_facts"


def _git_scope(saved: Any, probe: _GitProbe) -> dict[str, Any]:
    saved_probe, saved_fields, missing_saved_fields = _saved_git_scope(saved)
    comparison = _git_comparison(
        probe.state,
        saved_probe,
        missing_saved_fields,
    )
    checked_fields = [
        "aggregate_status_counts" if key == "status" else key
        for key in saved_fields
    ]
    return {
        "saved_probe": saved_probe,
        "current_probe": probe.state,
        "checked": probe.state != "unavailable",
        "comparison_complete": comparison == "checked_against_stored_facts",
        "comparison": comparison,
        "checked_fields": checked_fields,
        "missing_saved_fields": missing_saved_fields,
        "status_detail": "aggregate_counts_only",
        "excluded": [
            ".handoffs/**",
            "individual_paths",
            "remotes",
            "diffs",
            "logs",
        ],
    }


def _compare_artifacts(
    anchors: Any, *, root: Path, limits: Limits
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(anchors, list):
        return (
            [{"kind": "artifact_metadata_missing"}],
            {
                "coverage": "explicit_saved_anchors_only",
                "saved": 0,
                "checked": 0,
                "matched": 0,
                "changed": 0,
                "unavailable": 0,
                "metadata_valid": False,
            },
        )

    scope: dict[str, Any] = {
        "coverage": "explicit_saved_anchors_only",
        "saved": len(anchors),
        "checked": 0,
        "matched": 0,
        "changed": 0,
        "unavailable": 0,
        "metadata_valid": True,
    }
    drift: list[dict[str, Any]] = []
    for anchor in anchors:
        if not isinstance(anchor, Mapping):
            drift.append({"kind": "artifact_metadata_invalid"})
            scope["unavailable"] += 1
            continue
        name = anchor.get("name")
        path = anchor.get("path")
        expected = anchor.get("sha256")
        if not isinstance(name, str) or not isinstance(path, str):
            drift.append({"kind": "artifact_metadata_invalid"})
            scope["unavailable"] += 1
            continue
        try:
            current = hash_named_artifact(name, path, root=root, limits=limits)
        except (DomainError, OSError, ValueError):
            drift.append({"kind": "artifact_unavailable", "name": name, "path": path})
            scope["unavailable"] += 1
            continue
        scope["checked"] += 1
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
            scope["changed"] += 1
        else:
            scope["matched"] += 1
    return drift, scope


def _limited(values: list[Any], *, maximum: int = 5) -> tuple[list[Any], int]:
    selected = values[:maximum]
    return selected, len(values) - len(selected)


def _build_continuation(
    report: Mapping[str, Any], drift_scope: Mapping[str, Any]
) -> dict[str, Any]:
    actions = [
        dict(action)
        for action in report["next_actions"]
        if action.get("status") != "done"
    ]
    action_shortlist, omitted_actions = _limited(actions)
    textual_references, omitted_textual = _limited(list(report["artifacts"]))
    anchors = [
        {
            "name": anchor["name"],
            "path": anchor["path"],
            "sha256": anchor["sha256"],
        }
        for anchor in report["metadata"].get("artifact_anchors", [])
    ]
    anchored_references, omitted_anchors = _limited(anchors)
    suggested_skills, omitted_skills = _limited(list(report["suggested_skills"]))

    drift = list(report["drift"])
    artifact_scope = drift_scope["named_artifacts"]
    if drift:
        guidance = "review_drift"
    elif not drift_scope["git"]["comparison_complete"] or artifact_scope[
        "unavailable"
    ]:
        guidance = "verify_scope"
    else:
        guidance = "await_user_instruction"

    return {
        "mode": "report_only",
        "identity": {
            "handoff": report["handoff"],
            "sha256": report["sha256"],
            "body_sha256": report["body_sha256"],
            "file_sha256": report["file_sha256"],
        },
        "status": report["status"],
        "guidance": guidance,
        "goal": report["goal"],
        "exact_stopping_point": report["exact_stopping_point"],
        "drift": {
            "count": len(drift),
            "kinds": list(dict.fromkeys(item.get("kind") for item in drift)),
        },
        "drift_scope": dict(drift_scope),
        "canonical_references": {
            "textual": textual_references,
            "anchored": anchored_references,
            "omitted": omitted_textual + omitted_anchors,
        },
        "next_actions": {
            "items": action_shortlist,
            "omitted": omitted_actions,
        },
        "suggested_skills": {
            "items": suggested_skills,
            "omitted": omitted_skills,
        },
        "execution_authorized": False,
        "stop": "await_explicit_user_instruction",
    }


def resume(
    *,
    invocation_cwd: os.PathLike[str] | str,
    handoff_path: os.PathLike[str] | str,
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Validate and report one handoff without mutating project state."""

    root = resolve_project_root(invocation_cwd, limits=limits)
    parsed = load_handoff(root, handoff_path, limits=limits)
    git_probe = _collect_git_probe(root, limits=limits)
    drift = (
        _compare_git(parsed.metadata.get("git"), git_probe.facts)
        if git_probe.state != "unavailable"
        else []
    )
    artifact_drift, artifact_scope = _compare_artifacts(
        parsed.metadata.get("artifact_anchors"), root=root, limits=limits
    )
    drift.extend(artifact_drift)
    report = parsed.report()
    report["current_project"] = {
        "git": _git_dict(git_probe.facts),
        "git_probe": git_probe.state,
    }
    report["drift"] = drift
    report["status"] = "DRIFTED" if drift else "RESTORED"
    drift_scope = {
        "git": _git_scope(parsed.metadata.get("git"), git_probe),
        "named_artifacts": artifact_scope,
        "unchecked": {
            "database": "not_checked",
            "services": "not_checked",
            "external_references": "not_checked",
            "textual_artifacts_without_anchor": len(report["artifacts"]),
            "unnamed_file_contents": "not_checked",
        },
    }
    report["drift_scope"] = drift_scope
    report["continuation"] = _build_continuation(report, drift_scope)
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
