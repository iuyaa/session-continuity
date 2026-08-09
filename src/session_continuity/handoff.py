"""Canonical Session Continuity handoff format and publication."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .contracts import (
    DEFAULT_LIMITS,
    FilesystemError,
    InvalidInputError,
    LimitExceededError,
    Limits,
    PathSafetyError,
)
from .paths import (
    canonical_path,
    ensure_no_reparse_or_symlink,
    ensure_path_within,
    identity_from_stat,
    open_verified_readonly,
    stat_is_reparse_point,
)
from .redaction import (
    RedactionCounts,
    RedactionResult,
    assert_no_residual_sensitive_data,
    redact_output,
    redact_structured,
)

SCHEMA_VERSION = 1
HEADINGS = (
    "# Session Handoff",
    "## Metadata",
    "## Goal",
    "## Verified State",
    "## Reported State",
    "## In Progress",
    "## Deferred/Parked",
    "## Not Done",
    "## Decisions/Constraints",
    "## Files Changed",
    "## Commands Run",
    "## Verification",
    "## Artifacts",
    "## Environment",
    "## Evidence/Provenance",
    "## Exact Stopping Point",
    "## Next Actions",
    "## Suggested Skills",
    "## Privacy/Redactions",
)
TRAILER_RE = re.compile(
    rb"<!-- SESSION-CONTINUITY:COMPLETE schema=1 sha256=([0-9a-f]{64}) -->\n\Z"
)
_HEADING_RE = re.compile(r"(?m)^#{1,6} .+$")
_EVIDENCE_RE = re.compile(r"^E-[0-9]{3}$")
_CONTROL_RE = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩﻿]"
)
_ACTION_KEYS = frozenset(
    {"order", "status", "action", "targets", "depends_on", "acceptance", "evidence_refs"}
)
_ACTION_STATUSES = frozenset(
    {"pending", "ready", "blocked", "in_progress", "done", "parked"}
)
_ACTION_STATUS_ALIASES = {
    "pending": "pending",
    "not_started": "pending",
    "planned": "pending",
    "todo": "pending",
    "open": "pending",
    "待处理": "pending",
    "未开始": "pending",
    "ready": "ready",
    "actionable": "ready",
    "就绪": "ready",
    "已就绪": "ready",
    "blocked": "blocked",
    "waiting": "blocked",
    "waiting_on": "blocked",
    "受阻": "blocked",
    "阻塞": "blocked",
    "in_progress": "in_progress",
    "active": "in_progress",
    "started": "in_progress",
    "进行中": "in_progress",
    "done": "done",
    "complete": "done",
    "completed": "done",
    "完成": "done",
    "已完成": "done",
    "parked": "parked",
    "deferred": "parked",
    "搁置": "parked",
    "延期": "parked",
}
_LIST_KEYS = (
    "verified_state",
    "reported_state",
    "in_progress",
    "deferred_parked",
    "not_done",
    "decisions_constraints",
    "files_changed",
    "commands_run",
    "verification",
    "artifacts",
    "environment",
    "evidence_provenance",
    "suggested_skills",
)
_PAYLOAD_KEYS = frozenset({"goal", "exact_stopping_point", "next_actions", *_LIST_KEYS})
_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "created_at_local",
        "created_at_utc",
        "timezone_offset",
        "focus",
        "project_root",
        "root_mode",
        "git",
        "artifact_anchors",
    }
)
_GIT_KEYS = frozenset({"is_repository", "head", "branch", "detached", "status"})
_GIT_STATUS_KEYS = frozenset(
    {"entries", "staged", "unstaged", "untracked", "conflicted", "dirty"}
)
_ARTIFACT_KEYS = frozenset({"name", "path", "size", "mtime_ns", "sha256"})


@dataclass(frozen=True, slots=True)
class ParsedHandoff:
    """Validated handoff content and machine-readable fields."""

    path: Path | None
    sha256: str
    metadata: dict[str, Any]
    sections: dict[str, str]
    next_actions: tuple[dict[str, Any], ...]
    privacy: dict[str, Any]
    raw: bytes

    def report(self) -> dict[str, Any]:
        return {
            "mode": "report_only",
            "schema_version": SCHEMA_VERSION,
            "handoff": self.path.name if self.path else None,
            "sha256": self.sha256,
            "body_sha256": self.sha256,
            "file_sha256": hashlib.sha256(self.raw).hexdigest(),
            "metadata": self.metadata,
            "goal": self.sections["Goal"],
            "verified_state": _parse_list(self.sections["Verified State"]),
            "reported_state": _parse_list(self.sections["Reported State"]),
            "in_progress": _parse_list(self.sections["In Progress"]),
            "deferred_parked": _parse_list(self.sections["Deferred/Parked"]),
            "not_done": _parse_list(self.sections["Not Done"]),
            "decisions_constraints": _parse_list(
                self.sections["Decisions/Constraints"]
            ),
            "files_changed": _parse_list(self.sections["Files Changed"]),
            "commands_run": _parse_list(self.sections["Commands Run"]),
            "verification": _parse_list(self.sections["Verification"]),
            "artifacts": _parse_list(self.sections["Artifacts"]),
            "environment": _parse_list(self.sections["Environment"]),
            "evidence_provenance": _parse_list(
                self.sections["Evidence/Provenance"]
            ),
            "exact_stopping_point": self.sections["Exact Stopping Point"],
            "next_actions": list(self.next_actions),
            "suggested_skills": _parse_list(self.sections["Suggested Skills"]),
            "privacy": self.privacy,
        }


@dataclass(frozen=True, slots=True)
class Publication:
    """Verified result of one exclusive handoff publication."""

    path: Path
    sha256: str
    file_sha256: str
    created_local: str
    created_utc: str
    timezone_offset: str
    redactions: RedactionCounts
    size: int


def _strict_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise InvalidInputError("JSON object contains a duplicate key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise InvalidInputError("JSON contains a non-finite number")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except InvalidInputError:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        raise InvalidInputError("JSON block is malformed") from error


def _clean_text(value: Any, *, name: str, limits: Limits) -> str:
    if not isinstance(value, str):
        raise InvalidInputError(f"{name} must be text")
    normalized = unicodedata.normalize("NFC", value.strip())
    if len(normalized) > limits.max_text_chars:
        raise LimitExceededError(
            f"{name} exceeds the character limit",
            context={"limit": limits.max_text_chars},
        )
    if _CONTROL_RE.search(normalized):
        raise InvalidInputError(f"{name} contains a forbidden control character")
    return normalized


def _clean_list(value: Any, *, name: str, limits: Limits) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise InvalidInputError(f"{name} must be an array")
    if len(value) > limits.max_list_items:
        raise LimitExceededError(
            f"{name} exceeds the item limit",
            context={"limit": limits.max_list_items},
        )
    return [_clean_text(item, name=name, limits=limits) for item in value]


def _clean_action_status(value: Any, *, limits: Limits) -> str:
    supplied = _clean_text(value, name="status", limits=limits)
    key = re.sub(r"_+", "_", supplied.casefold().replace("-", "_").replace(" ", "_"))
    status = _ACTION_STATUS_ALIASES.get(key)
    if status is None or status not in _ACTION_STATUSES:
        raise InvalidInputError(
            "Next Action status is invalid; use pending, ready, blocked, "
            "in_progress, done, or parked"
        )
    return status


def _project_relative_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    if ":" in normalized:
        raise InvalidInputError("artifact path must not contain a drive or stream")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or not candidate.parts:
        raise InvalidInputError("artifact path must be project-relative")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise InvalidInputError("artifact path contains traversal")
    if candidate.parts[0].casefold() == ".handoffs":
        raise InvalidInputError("artifact path cannot reference .handoffs")
    return candidate.as_posix()


def _clean_targets(value: Any, *, limits: Limits) -> list[str]:
    targets = _clean_list(value, name="targets", limits=limits)
    if any(not target for target in targets):
        raise InvalidInputError("Next Action targets must not contain empty values")
    return targets


def _clean_actions(value: Any, *, limits: Limits) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise InvalidInputError("next_actions must be an array")
    if len(value) > limits.max_actions:
        raise LimitExceededError(
            "next_actions exceeds the action limit",
            context={"limit": limits.max_actions},
        )
    actions: list[dict[str, Any]] = []
    for index, raw in enumerate(value, 1):
        if not isinstance(raw, Mapping):
            raise InvalidInputError("each Next Action must be an object")
        unknown = set(raw) - _ACTION_KEYS
        if unknown:
            raise InvalidInputError("Next Action contains an unknown field")
        order = raw.get("order", index)
        if isinstance(order, bool) or not isinstance(order, int) or order != index:
            raise InvalidInputError("Next Action order must be contiguous from one")
        status = _clean_action_status(raw.get("status", "pending"), limits=limits)
        action = _clean_text(raw.get("action", ""), name="action", limits=limits)
        if not action:
            raise InvalidInputError("Next Action action must not be empty")
        targets = _clean_targets(raw.get("targets", []), limits=limits)
        depends_on = _clean_list(
            raw.get("depends_on", []), name="depends_on", limits=limits
        )
        acceptance = _clean_text(
            raw.get("acceptance", ""), name="acceptance", limits=limits
        )
        evidence_refs = _clean_list(
            raw.get("evidence_refs", []), name="evidence_refs", limits=limits
        )
        if any(not _EVIDENCE_RE.fullmatch(ref) for ref in evidence_refs):
            raise InvalidInputError("Next Action evidence_refs must use E-###")
        actions.append(
            {
                "order": order,
                "status": status,
                "action": action,
                "targets": targets,
                "depends_on": depends_on,
                "acceptance": acceptance,
                "evidence_refs": evidence_refs,
            }
        )
    return actions


def normalize_payload(value: Any, *, limits: Limits = DEFAULT_LIMITS) -> dict[str, Any]:
    """Validate and normalize the model-supplied create payload."""

    if not isinstance(value, Mapping):
        raise InvalidInputError("create input must be an object")
    unknown = set(value) - _PAYLOAD_KEYS
    if unknown:
        raise InvalidInputError("create input contains an unknown field")
    normalized: dict[str, Any] = {
        "goal": _clean_text(value.get("goal", ""), name="goal", limits=limits),
        "exact_stopping_point": _clean_text(
            value.get("exact_stopping_point", ""),
            name="exact_stopping_point",
            limits=limits,
        ),
        "next_actions": _clean_actions(value.get("next_actions", []), limits=limits),
    }
    if not normalized["goal"]:
        raise InvalidInputError("goal must not be empty")
    for key in _LIST_KEYS:
        normalized[key] = _clean_list(value.get(key, []), name=key, limits=limits)
    defined_evidence = {
        item.split(":", 1)[0].strip()
        for item in normalized["evidence_provenance"]
        if ":" in item and _EVIDENCE_RE.fullmatch(item.split(":", 1)[0].strip())
    }
    for action in normalized["next_actions"]:
        if any(ref not in defined_evidence for ref in action["evidence_refs"]):
            raise InvalidInputError("Next Action references undefined evidence")
    return normalized


def _list_markdown(values: Sequence[str]) -> str:
    return "\n".join(f"- {item}" for item in values) if values else "- None."


def _json_block(value: Any) -> str:
    return "```json\n" + json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    ) + "\n```"


def _render_body(
    payload: Mapping[str, Any], metadata: Mapping[str, Any], privacy: Mapping[str, Any]
) -> str:
    sections = {
        "Metadata": _json_block(metadata),
        "Goal": payload["goal"] or "None recorded.",
        "Verified State": _list_markdown(payload["verified_state"]),
        "Reported State": _list_markdown(payload["reported_state"]),
        "In Progress": _list_markdown(payload["in_progress"]),
        "Deferred/Parked": _list_markdown(payload["deferred_parked"]),
        "Not Done": _list_markdown(payload["not_done"]),
        "Decisions/Constraints": _list_markdown(payload["decisions_constraints"]),
        "Files Changed": _list_markdown(payload["files_changed"]),
        "Commands Run": _list_markdown(payload["commands_run"]),
        "Verification": _list_markdown(payload["verification"]),
        "Artifacts": _list_markdown(payload["artifacts"]),
        "Environment": _list_markdown(payload["environment"]),
        "Evidence/Provenance": _list_markdown(payload["evidence_provenance"]),
        "Exact Stopping Point": payload["exact_stopping_point"] or "None recorded.",
        "Next Actions": _json_block(payload["next_actions"]),
        "Suggested Skills": _list_markdown(payload["suggested_skills"]),
        "Privacy/Redactions": _json_block(privacy),
    }
    output = [HEADINGS[0]]
    for heading in HEADINGS[1:]:
        name = heading[3:]
        output.extend(("", heading, "", sections[name]))
    return "\n".join(output) + "\n"


def _privacy_block(counts: RedactionCounts) -> dict[str, Any]:
    return {"categories": counts.as_dict(), "total": counts.total}


def render_document(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[bytes, str, RedactionCounts]:
    """Redact, render, hash, and self-validate one handoff document."""

    structured: RedactionResult[Any] = redact_structured(
        {"payload": dict(payload), "metadata": dict(metadata)}, limits=limits
    )
    clean_payload = structured.value["payload"]
    clean_metadata = structured.value["metadata"]
    body = _render_body(clean_payload, clean_metadata, _privacy_block(structured.counts))
    output = redact_output(body, limits=limits)
    counts = structured.counts.merged(output.counts)
    if output.counts.total:
        privacy_pattern = re.compile(
            r"(?ms)^## Privacy/Redactions\n\n```json\n.*?\n```\n\Z"
        )
        replacement = "## Privacy/Redactions\n\n" + _json_block(_privacy_block(counts)) + "\n"
        body = privacy_pattern.sub(replacement, output.value)
    else:
        body = output.value
    assert_no_residual_sensitive_data(body)
    body_bytes = body.encode("utf-8")
    digest = hashlib.sha256(body_bytes).hexdigest()
    trailer = (
        f"<!-- SESSION-CONTINUITY:COMPLETE schema={SCHEMA_VERSION} "
        f"sha256={digest} -->\n"
    ).encode("ascii")
    document = body_bytes + trailer
    if len(document) > limits.max_handoff_bytes:
        raise LimitExceededError(
            "handoff exceeds the byte limit",
            context={"limit": limits.max_handoff_bytes},
        )
    parse_document(document, limits=limits)
    return document, digest, counts


def _extract_json_block(section: str, *, name: str) -> Any:
    match = re.fullmatch(r"```json\n(.*)\n```", section, flags=re.DOTALL)
    if match is None:
        raise InvalidInputError(f"{name} must contain exactly one JSON block")
    return _strict_json(match.group(1))


def _validate_git_metadata(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or "is_repository" not in value
        or set(value) - _GIT_KEYS
        or not isinstance(value["is_repository"], bool)
    ):
        raise InvalidInputError("handoff Git metadata is invalid")
    for key in ("detached",):
        if key in value and not isinstance(value[key], bool):
            raise InvalidInputError("handoff Git metadata is invalid")
    for key in ("head", "branch"):
        if key in value and value[key] is not None and not isinstance(value[key], str):
            raise InvalidInputError("handoff Git metadata is invalid")
    if "status" not in value:
        return
    status = value["status"]
    if not isinstance(status, dict) or set(status) != _GIT_STATUS_KEYS:
        raise InvalidInputError("handoff Git status metadata is invalid")
    for key in ("entries", "staged", "unstaged", "untracked", "conflicted"):
        count = status[key]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvalidInputError("handoff Git status metadata is invalid")
    if not isinstance(status["dirty"], bool):
        raise InvalidInputError("handoff Git status metadata is invalid")


def _validate_metadata(value: Any, *, limits: Limits) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _METADATA_KEYS:
        raise InvalidInputError("handoff metadata schema is invalid")
    if value["schema_version"] != SCHEMA_VERSION:
        raise InvalidInputError("handoff metadata schema is invalid")
    if value["root_mode"] not in {"git", "cwd"} or value["project_root"] != ".":
        raise InvalidInputError("handoff project binding is invalid")
    for key in ("created_at_local", "created_at_utc", "timezone_offset", "focus"):
        if not isinstance(value[key], str):
            raise InvalidInputError("handoff metadata value is invalid")
    try:
        local = datetime.fromisoformat(value["created_at_local"])
        utc = datetime.fromisoformat(value["created_at_utc"].replace("Z", "+00:00"))
    except ValueError as error:
        raise InvalidInputError("handoff timestamps are invalid") from error
    if (
        not value["created_at_utc"].endswith("Z")
        or local.utcoffset() is None
        or utc.utcoffset() != timezone.utc.utcoffset(None)
        or local.astimezone(timezone.utc) != utc
        or value["timezone_offset"] != local.strftime("%z")
        or not re.fullmatch(r"[+-][0-9]{4}", value["timezone_offset"])
    ):
        raise InvalidInputError("handoff timestamps are invalid")
    _validate_git_metadata(value["git"])
    anchors = value["artifact_anchors"]
    if not isinstance(anchors, list) or len(anchors) > limits.max_artifacts:
        raise InvalidInputError("handoff artifact metadata is invalid")
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != _ARTIFACT_KEYS:
            raise InvalidInputError("handoff artifact metadata is invalid")
        if not isinstance(anchor["name"], str) or not anchor["name"]:
            raise InvalidInputError("handoff artifact metadata is invalid")
        if not isinstance(anchor["path"], str):
            raise InvalidInputError("handoff artifact metadata is invalid")
        _project_relative_path(anchor["path"])
        for key in ("size", "mtime_ns"):
            number = anchor[key]
            if isinstance(number, bool) or not isinstance(number, int) or number < 0:
                raise InvalidInputError("handoff artifact metadata is invalid")
        if not isinstance(anchor["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", anchor["sha256"]
        ):
            raise InvalidInputError("handoff artifact metadata is invalid")
    return value


def _validate_privacy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"categories", "total"}:
        raise InvalidInputError("handoff privacy data is invalid")
    categories = value["categories"]
    expected = {category.value for category in RedactionCounts({}).counts}
    if not isinstance(categories, dict) or set(categories) != expected:
        raise InvalidInputError("handoff privacy data is invalid")
    total = 0
    for count in categories.values():
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvalidInputError("handoff privacy data is invalid")
        total += count
    if isinstance(value["total"], bool) or value["total"] != total:
        raise InvalidInputError("handoff privacy total is invalid")
    return value


def _split_sections(body: str) -> dict[str, str]:
    matches = list(_HEADING_RE.finditer(body))
    headings = tuple(match.group(0) for match in matches)
    if headings != HEADINGS or not matches or matches[0].start() != 0:
        raise InvalidInputError("handoff headings are missing, duplicated, or out of order")
    sections: dict[str, str] = {}
    for index, match in enumerate(matches[1:], 1):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        content = body[start:end]
        if not content.startswith("\n\n"):
            raise InvalidInputError("handoff section spacing is not canonical")
        expected_suffix = "\n" if index + 1 == len(matches) else "\n\n"
        if not content.endswith(expected_suffix):
            raise InvalidInputError("handoff section spacing is not canonical")
        if expected_suffix == "\n" and content.endswith("\n\n"):
            raise InvalidInputError("handoff final spacing is not canonical")
        sections[match.group(0)[3:]] = content[2 : -len(expected_suffix)]
    return sections


def parse_document(
    data: bytes, *, path: Path | None = None, limits: Limits = DEFAULT_LIMITS
) -> ParsedHandoff:
    """Strictly validate a complete handoff byte sequence."""

    if len(data) > limits.max_handoff_bytes:
        raise LimitExceededError(
            "handoff exceeds the byte limit", context={"limit": limits.max_handoff_bytes}
        )
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data or b"\x00" in data:
        raise InvalidInputError("handoff encoding is not canonical UTF-8/LF")
    trailer = TRAILER_RE.search(data)
    if trailer is None:
        raise InvalidInputError("handoff completion trailer is missing or invalid")
    body_bytes = data[: trailer.start()]
    actual_hash = hashlib.sha256(body_bytes).hexdigest()
    expected_hash = trailer.group(1).decode("ascii")
    if actual_hash != expected_hash:
        raise InvalidInputError("handoff content hash does not match")
    try:
        body = body_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise InvalidInputError("handoff is not strict UTF-8") from error
    if _CONTROL_RE.search(body):
        raise InvalidInputError("handoff contains a forbidden control character")
    assert_no_residual_sensitive_data(body)
    sections = _split_sections(body)
    metadata = _validate_metadata(
        _extract_json_block(sections["Metadata"], name="Metadata"), limits=limits
    )
    actions = _extract_json_block(sections["Next Actions"], name="Next Actions")
    privacy = _validate_privacy(
        _extract_json_block(
            sections["Privacy/Redactions"], name="Privacy/Redactions"
        )
    )
    normalized_actions = _clean_actions(actions, limits=limits)
    defined_evidence = {
        item.split(":", 1)[0].strip()
        for item in _parse_list(sections["Evidence/Provenance"])
        if ":" in item and _EVIDENCE_RE.fullmatch(item.split(":", 1)[0].strip())
    }
    for action in normalized_actions:
        if any(ref not in defined_evidence for ref in action["evidence_refs"]):
            raise InvalidInputError("Next Action references undefined evidence")
    return ParsedHandoff(
        path=path,
        sha256=actual_hash,
        metadata=metadata,
        sections=sections,
        next_actions=tuple(normalized_actions),
        privacy=privacy,
        raw=data,
    )


def _parse_list(section: str) -> list[str]:
    if section == "- None.":
        return []
    lines = section.splitlines()
    if any(not line.startswith("- ") for line in lines):
        raise InvalidInputError("handoff list section is malformed")
    return [line[2:] for line in lines]


def _local_instant() -> tuple[datetime, datetime, str]:
    try:
        local = datetime.now().astimezone()
        if local.utcoffset() is None:
            raise ValueError("local timezone has no offset")
    except (OSError, ValueError):
        local = datetime.now(timezone.utc)
    utc = local.astimezone(timezone.utc)
    offset = local.strftime("%z") or "+0000"
    return local, utc, offset


def _slug(focus: str, *, limits: Limits) -> str:
    safe = redact_output(focus, limits=limits).value if focus else "continuity"
    folded = unicodedata.normalize("NFKD", safe).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", folded.casefold()).strip("-")
    return (slug[:48].rstrip("-") or "continuity")


def build_metadata(
    *,
    focus: str,
    root_mode: str,
    git: Mapping[str, Any],
    artifact_anchors: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], datetime, datetime, str]:
    local, utc, offset = _local_instant()
    return (
        {
            "schema_version": SCHEMA_VERSION,
            "created_at_local": local.isoformat(timespec="seconds"),
            "created_at_utc": utc.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "timezone_offset": offset,
            "focus": focus,
            "project_root": ".",
            "root_mode": root_mode,
            "git": dict(git),
            "artifact_anchors": [dict(anchor) for anchor in artifact_anchors],
        },
        local,
        utc,
        offset,
    )


def _ensure_handoff_directory(root: Path) -> Path:
    destination = root / ".handoffs"
    try:
        os.mkdir(destination)
    except FileExistsError:
        pass
    except OSError as error:
        raise FilesystemError("handoff directory could not be created") from error
    checked = ensure_no_reparse_or_symlink(destination, root)
    info = os.stat(checked, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise PathSafetyError("handoff destination is not a safe directory")
    return checked


def _exclusive_write(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = -1
    created_identity = None
    failure: BaseException | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        created_identity = identity_from_stat(os.fstat(descriptor))
        view = memoryview(data)
        written = 0
        while written < len(view):
            try:
                count = os.write(descriptor, view[written:])
            except InterruptedError:
                continue
            if count <= 0:
                raise FilesystemError("handoff write made no progress")
            written += count
        os.fsync(descriptor)
    except FileExistsError:
        raise
    except (OSError, FilesystemError) as error:
        failure = FilesystemError("handoff publication failed")
        failure.__cause__ = error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                if failure is None:
                    failure = FilesystemError("handoff close failed")
                    failure.__cause__ = error
    if failure is not None:
        if created_identity is not None:
            _cleanup_created(path, created_identity)
        raise failure
    if created_identity is None:
        raise FilesystemError("handoff publication did not create a file")


def _cleanup_created(path: Path, expected: Any) -> None:
    try:
        current = identity_from_stat(os.stat(path, follow_symlinks=False))
        if expected.same_object(current):
            os.unlink(path)
    except OSError:
        return


def publish_handoff(
    root: os.PathLike[str] | str,
    payload: Mapping[str, Any],
    *,
    focus: str = "",
    root_mode: str,
    git: Mapping[str, Any],
    artifact_anchors: Sequence[Mapping[str, Any]] = (),
    limits: Limits = DEFAULT_LIMITS,
) -> Publication:
    """Publish one exclusive, read-back-verified handoff."""

    project_root = canonical_path(root, strict=True, limits=limits)
    normalized = normalize_payload(payload, limits=limits)
    clean_focus = _clean_text(focus, name="focus", limits=limits)
    metadata, local, utc, offset = build_metadata(
        focus=clean_focus,
        root_mode=root_mode,
        git=git,
        artifact_anchors=artifact_anchors,
    )
    document, digest, counts = render_document(normalized, metadata, limits=limits)
    directory = _ensure_handoff_directory(project_root)
    timestamp = local.strftime("%Y%m%dT%H%M%S") + offset
    base = f"{timestamp}-{_slug(clean_focus, limits=limits)}"
    for _ in range(8):
        path = directory / f"{base}-{secrets.token_hex(4)}.md"
        try:
            _exclusive_write(path, document)
        except FileExistsError:
            continue
        identity = identity_from_stat(os.stat(path, follow_symlinks=False))
        try:
            with open_verified_readonly(path, directory, limits=limits) as stream:
                readback = stream.read(limits.max_handoff_bytes + 1)
            if readback != document:
                raise FilesystemError("handoff readback differs from written bytes")
            parsed = parse_document(readback, path=path, limits=limits)
            if parsed.sha256 != digest:
                raise FilesystemError("handoff readback hash differs")
        except BaseException:
            _cleanup_created(path, identity)
            raise
        return Publication(
            path=path,
            sha256=digest,
            file_sha256=hashlib.sha256(document).hexdigest(),
            created_local=local.isoformat(timespec="seconds"),
            created_utc=utc.isoformat(timespec="seconds").replace("+00:00", "Z"),
            timezone_offset=offset,
            redactions=counts,
            size=len(document),
        )
    raise FilesystemError("handoff filename collisions exceeded retry limit")


def load_handoff(
    root: os.PathLike[str] | str,
    handoff_path: os.PathLike[str] | str,
    *,
    limits: Limits = DEFAULT_LIMITS,
) -> ParsedHandoff:
    """Read and validate one exact handoff without mutation."""

    project_root = canonical_path(root, strict=True, limits=limits)
    handoff_root = ensure_path_within(project_root / ".handoffs", project_root)
    supplied = Path(handoff_path)
    candidate = supplied if supplied.is_absolute() else project_root / supplied
    contained = ensure_path_within(candidate, handoff_root, allow_equal=False, limits=limits)
    if contained.parent != handoff_root or contained.suffix.casefold() != ".md":
        raise PathSafetyError("resume requires one direct .handoffs Markdown file")
    ensure_no_reparse_or_symlink(candidate, handoff_root, limits=limits)
    with open_verified_readonly(candidate, handoff_root, limits=limits) as stream:
        data = stream.read(limits.max_handoff_bytes + 1)
    return parse_document(data, path=contained, limits=limits)
