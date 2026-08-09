"""Read-only recovery of Claude Code and Codex JSONL sessions.

The module deliberately has no persistence layer.  Every file is opened read-only,
its size is captured from the open descriptor, and parsing stops at that captured
boundary even if a writer appends more data concurrently.
"""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .contracts import DomainError
from .paths import open_verified_readonly

__all__ = [
    "EvidenceEvent",
    "EvidenceGap",
    "RecoveryLimits",
    "SessionDescriptor",
    "SessionSelector",
    "reconstruct",
]

_UUID_RE = re.compile(
    r"(?i)(?<![0-9a-f])"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"(?![0-9a-f])"
)
_WORD_RE = re.compile(r"[a-z0-9_][a-z0-9_.:/-]{1,63}", re.IGNORECASE)
_CJK_RE = re.compile(r"[㐀-鿿]+")
_SENSITIVE_NAMES = {
    "analysis",
    "chain_of_thought",
    "encrypted",
    "encrypted_content",
    "reasoning",
    "reasoning_content",
    "redacted_reasoning",
    "redacted_thinking",
    "signature",
    "thinking",
    "thinking_content",
}
_SENSITIVE_TAG_RE = re.compile(
    r"<(?P<tag>thinking|reasoning|analysis|signature|encrypted(?:_?content)?|"
    r"redacted_?(?:thinking|reasoning))\b[^>]*>"
    r".*?</(?P=tag)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_LINE_RE = re.compile(
    r"(?im)^\s*['\"]?(?:thinking(?:_?content)?|reasoning(?:_?content)?|analysis|"
    r"signature(?:_?content)?|encrypted(?:_?content)?|redacted_?(?:thinking|reasoning))"
    r"['\"]?\s*[:=].*$"
)
_LINK_KEYS = {
    "output_file": "tool_result",
    "output_path": "tool_result",
    "result_file": "tool_result",
    "result_path": "tool_result",
    "transcript_file": "subagent",
    "transcript_path": "subagent",
    "session_file": "subagent",
    "session_path": "subagent",
}
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "for",
    "from",
    "in",
    "of",
    "on",
    "or",
    "the",
    "to",
    "with",
}


@dataclass(frozen=True, slots=True)
class RecoveryLimits:
    """Hard bounds applied to discovery, parsing, links, and returned content."""

    max_sessions: int = 8
    max_candidates: int = 256
    max_discovery_entries: int = 10_000
    max_session_bytes: int = 512 * 1024 * 1024
    max_total_session_bytes: int = 2 * 1024 * 1024 * 1024
    max_topic_scan_bytes: int = 256 * 1024
    max_line_bytes: int = 1024 * 1024
    max_events: int = 300
    max_event_chars: int = 16_000
    max_output_chars: int = 240_000
    max_evidence_gaps: int = 128
    max_link_files: int = 8
    max_link_bytes: int = 512 * 1024
    max_path_chars: int = 2_048
    max_structured_items: int = 64
    max_structured_depth: int = 6
    topic_threshold: float = 0.70

    def __post_init__(self) -> None:
        integer_fields = (
            "max_sessions",
            "max_candidates",
            "max_discovery_entries",
            "max_session_bytes",
            "max_total_session_bytes",
            "max_topic_scan_bytes",
            "max_line_bytes",
            "max_events",
            "max_event_chars",
            "max_output_chars",
            "max_evidence_gaps",
            "max_link_files",
            "max_link_bytes",
            "max_path_chars",
            "max_structured_items",
            "max_structured_depth",
        )
        for name in integer_fields:
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if not 0.0 <= self.topic_threshold <= 1.0:
            raise ValueError("topic_threshold must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class SessionSelector:
    """A normalized selector: ``path``, ``id``, or ``topic``."""

    kind: str
    value: str

    @classmethod
    def parse(cls, value: Any) -> "SessionSelector":
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            kind = str(value.get("kind", value.get("type", ""))).strip().lower()
            selected = value.get("value", value.get(kind))
            if kind in {"path", "id", "topic"} and selected is not None:
                return cls(kind, str(selected).strip())
            raise ValueError("selector mapping needs kind and value")
        if isinstance(value, os.PathLike):
            return cls("path", os.fspath(value))
        if not isinstance(value, str):
            raise TypeError("selector must be a string, path, mapping, or SessionSelector")

        raw = value.strip()
        for prefix in ("path:", "id:", "topic:"):
            if raw.lower().startswith(prefix):
                selected = raw[len(prefix) :].strip()
                if not selected:
                    raise ValueError(f"{prefix[:-1]} selector is empty")
                if prefix == "id:":
                    selected = _canonical_uuid(selected) or selected
                return cls(prefix[:-1], selected)
        canonical = _canonical_uuid(raw)
        if canonical is not None:
            return cls("id", canonical)
        if _looks_like_path(raw):
            return cls("path", raw)
        if not raw:
            raise ValueError("topic selector is empty")
        return cls("topic", raw)

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True, slots=True)
class SessionDescriptor:
    """A discovered session and, after reading, its descriptor snapshot."""

    provider: str
    session_id: str
    path: str
    archived: bool = False
    project_hint: str | None = None
    mtime_ns: int | None = None
    captured_size: int | None = None
    topic_score: float | None = None
    source_root: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "provider": self.provider,
            "session_id": self.session_id,
            "path": self.path,
            "archived": self.archived,
        }
        if self.project_hint is not None:
            result["project_hint"] = self.project_hint
        if self.mtime_ns is not None:
            result["mtime_ns"] = self.mtime_ns
        if self.captured_size is not None:
            result["captured_size"] = self.captured_size
        if self.topic_score is not None:
            result["topic_score"] = round(self.topic_score, 4)
        return result


@dataclass(slots=True)
class EvidenceEvent:
    """Visible evidence extracted from a session or a structured linked artifact."""

    source_session: str
    provider: str
    kind: str
    role: str | None
    content: str
    timestamp: str | None = None
    sequence: int = 0
    event_id: str | None = None
    tool_call_id: str | None = None
    details: dict[str, Any] | None = None
    source_artifact: str | None = None
    also_seen_in: list[str] = field(default_factory=list)
    origin: str = field(default="", repr=False)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source_session": self.source_session,
            "provider": self.provider,
            "kind": self.kind,
            "content": self.content,
            "sequence": self.sequence,
        }
        if self.role is not None:
            result["role"] = self.role
        if self.timestamp is not None:
            result["timestamp"] = self.timestamp
        if self.event_id is not None:
            result["event_id"] = self.event_id
        if self.tool_call_id is not None:
            result["tool_call_id"] = self.tool_call_id
        if self.details:
            result["details"] = self.details
        if self.source_artifact is not None:
            result["source_artifact"] = self.source_artifact
        if self.also_seen_in:
            result["also_seen_in"] = list(self.also_seen_in)
        return result


@dataclass(frozen=True, slots=True)
class EvidenceGap:
    """A bounded description of evidence that could not be consumed."""

    source_session: str
    kind: str
    detail: str
    line: int | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source_session": self.source_session,
            "kind": self.kind,
            "detail": self.detail,
        }
        if self.line is not None:
            result["line"] = self.line
        if self.path is not None:
            result["path"] = self.path
        return result


@dataclass(frozen=True, slots=True)
class _StructuredLink:
    path: str
    kind: str


@dataclass(slots=True)
class _ParseState:
    provider: str
    session_id: str
    path: str
    project_hints: set[str] = field(default_factory=set)
    force_session_id: bool = False


class _Collector:
    def __init__(self, limits: RecoveryLimits) -> None:
        self.limits = limits
        self.events: list[EvidenceEvent] = []
        self.gaps: list[EvidenceGap] = []
        self.linked_sources: list[dict[str, Any]] = []
        self.char_count = 0
        self.truncated = False
        self._sequence = 0
        self._stable_seen: dict[tuple[str, str, str], int] = {}
        self._recent_semantic: dict[tuple[Any, ...], tuple[int, int, str]] = {}
        self._gap_limit_noted = False

    def add_gap(
        self,
        source_session: str,
        kind: str,
        detail: str,
        *,
        line: int | None = None,
        path: str | None = None,
    ) -> None:
        if len(self.gaps) >= self.limits.max_evidence_gaps:
            self.truncated = True
            self._gap_limit_noted = True
            return
        self.gaps.append(
            EvidenceGap(
                source_session=_bounded_text(source_session, 256),
                kind=_bounded_text(kind, 96),
                detail=_bounded_text(detail, 512),
                line=line,
                path=_bounded_text(path, self.limits.max_path_chars) if path else None,
            )
        )

    def add_event(self, event: EvidenceEvent) -> bool:
        if len(self.events) >= self.limits.max_events:
            self.truncated = True
            self.add_gap(
                event.source_session,
                "event_limit",
                f"event output stopped at {self.limits.max_events} records",
                path=event.source_artifact,
            )
            return False

        content = _clean_visible_text(event.content)
        if not content:
            return False
        if len(content) > self.limits.max_event_chars:
            original_length = len(content)
            content = content[: self.limits.max_event_chars - 1] + "…"
            self.add_gap(
                event.source_session,
                "event_content_limit",
                f"event content truncated from {original_length} characters",
                path=event.source_artifact,
            )
            self.truncated = True

        details = _sanitize_structured(event.details, self.limits) if event.details else None
        detail_chars = len(_json_compact(details)) if details else 0
        projected = len(content) + detail_chars
        available = self.limits.max_output_chars - self.char_count
        if projected > available:
            reserve = detail_chars + 1
            content_room = available - reserve
            if content_room <= 0:
                self.truncated = True
                self.add_gap(
                    event.source_session,
                    "output_char_limit",
                    f"visible output stopped at {self.limits.max_output_chars} characters",
                    path=event.source_artifact,
                )
                return False
            content = content[: max(0, content_room - 1)] + "…"
            projected = len(content) + detail_chars
            self.truncated = True
            self.add_gap(
                event.source_session,
                "output_char_limit",
                f"visible output reached {self.limits.max_output_chars} characters",
                path=event.source_artifact,
            )

        event.content = content
        event.details = details if isinstance(details, dict) else None
        event.sequence = self._sequence
        self._sequence += 1

        stable_key: tuple[str, str, str] | None = None
        if event.event_id:
            stable_scope = (
                "global" if _canonical_uuid(event.event_id) else event.source_session
            )
            stable_key = (stable_scope, event.kind, event.event_id)
            previous_index = self._stable_seen.get(stable_key)
            if previous_index is not None:
                previous = self.events[previous_index]
                if event.source_session != previous.source_session:
                    if event.source_session not in previous.also_seen_in:
                        previous.also_seen_in.append(event.source_session)
                return False

        semantic_key = (
            event.source_session,
            event.kind,
            event.role,
            event.content,
            event.tool_call_id,
            _json_compact(event.details) if event.details else "",
        )
        previous_semantic = self._recent_semantic.get(semantic_key)
        if previous_semantic is not None:
            previous_index, previous_sequence, previous_origin = previous_semantic
            wrappers = {previous_origin, event.origin}
            if (
                event.sequence - previous_sequence <= 6
                and previous_origin != event.origin
                and wrappers <= {"codex_event", "codex_item"}
            ):
                previous = self.events[previous_index]
                if event.source_session != previous.source_session:
                    if event.source_session not in previous.also_seen_in:
                        previous.also_seen_in.append(event.source_session)
                return False

        index = len(self.events)
        self.events.append(event)
        self.char_count += projected
        if stable_key is not None:
            self._stable_seen[stable_key] = index
        self._recent_semantic[semantic_key] = (index, event.sequence, event.origin)
        return True


# Public entry point ---------------------------------------------------------


def reconstruct(
    selector: Any,
    project_root: str | os.PathLike[str],
    *,
    limits: RecoveryLimits | None = None,
    home: str | os.PathLike[str] | None = None,
    claude_root: str | os.PathLike[str] | None = None,
    codex_root: str | os.PathLike[str] | None = None,
    max_sessions: int | None = None,
    max_events: int | None = None,
    max_bytes: int | None = None,
    max_line_bytes: int | None = None,
    max_output_chars: int | None = None,
    topic_threshold: float | None = None,
    follow_structured_links: bool = True,
) -> dict[str, Any]:
    """Reconstruct a bounded, serializable report without mutating any file.

    ``selector`` accepts a path, an exact UUID, a topic string, a
    :class:`SessionSelector`, or ``{"kind": ..., "value": ...}``.  Prefixes
    ``path:``, ``id:``, and ``topic:`` remove any ambiguity.  ``home`` and the
    two root arguments are primarily useful for isolated fixtures.
    """

    effective = limits or RecoveryLimits()
    overrides: dict[str, Any] = {}
    if max_sessions is not None:
        overrides["max_sessions"] = max_sessions
    if max_events is not None:
        overrides["max_events"] = max_events
    if max_bytes is not None:
        overrides["max_session_bytes"] = max_bytes
    if max_line_bytes is not None:
        overrides["max_line_bytes"] = max_line_bytes
    if max_output_chars is not None:
        overrides["max_output_chars"] = max_output_chars
    if topic_threshold is not None:
        overrides["topic_threshold"] = topic_threshold
    if overrides:
        effective = replace(effective, **overrides)

    collector = _Collector(effective)
    project = _absolute_path(os.fspath(project_root), None)
    base_home = Path(home).expanduser() if home is not None else Path.home()
    claude = (
        _absolute_path(os.fspath(claude_root), base_home)
        if claude_root is not None
        else base_home / ".claude" / "projects"
    )
    codex = (
        _absolute_path(os.fspath(codex_root), base_home)
        if codex_root is not None
        else base_home / ".codex"
    )

    try:
        normalized_selector = SessionSelector.parse(selector)
    except (TypeError, ValueError) as exc:
        collector.add_gap("selector", "invalid_selector", str(exc))
        return _build_report(
            SessionSelector("topic", ""), project, [], collector, effective
        )
    if (
        normalized_selector.kind == "topic"
        and len(normalized_selector.value) > effective.max_event_chars
    ):
        collector.add_gap(
            "selector",
            "selector_limit",
            f"topic bounded to {effective.max_event_chars} characters",
        )
        collector.truncated = True
        normalized_selector = replace(
            normalized_selector,
            value=normalized_selector.value[: effective.max_event_chars],
        )

    selected: list[SessionDescriptor]
    if normalized_selector.kind == "path":
        explicit = _absolute_path(normalized_selector.value, base_home)
        allowed_root = _allowed_explicit_root(explicit, project, claude, codex)
        if allowed_root is None:
            collector.add_gap(
                "selector",
                "path_outside_allowed_roots",
                "explicit session path is outside the project and supported session roots",
            )
            selected = []
        else:
            selected = [_descriptor_for_path(explicit, effective, allowed_root)]
    elif normalized_selector.kind == "id":
        selected = _select_exact(
            normalized_selector.value, claude, codex, effective, collector
        )
    else:
        selected = _select_topic(
            normalized_selector.value,
            project,
            claude,
            codex,
            effective,
            collector,
        )

    recovered: list[SessionDescriptor] = []
    # Oldest first gives deterministic sequence numbers; final output is then
    # merged chronologically across sources.
    parse_order = sorted(
        selected,
        key=lambda item: (
            item.mtime_ns if item.mtime_ns is not None else 0,
            item.provider,
            item.path,
        ),
    )
    total_remaining = effective.max_total_session_bytes
    for descriptor in parse_order:
        if total_remaining <= 0:
            collector.add_gap(
                "selector",
                "total_session_byte_limit",
                f"selected session reads reached {effective.max_total_session_bytes} bytes",
            )
            collector.truncated = True
            break
        session_limit = min(effective.max_session_bytes, total_remaining)
        parsed = _read_session(
            descriptor,
            collector,
            effective,
            byte_limit=session_limit,
            follow_links=follow_structured_links,
        )
        consumed = min(parsed.captured_size or 0, session_limit)
        total_remaining -= consumed
        recovered.append(parsed)
        if len(collector.events) >= effective.max_events:
            break

    recovered_by_path = {item.path: item for item in recovered}
    sessions = [recovered_by_path.get(item.path, item) for item in selected]
    _sort_events(collector.events, sessions)
    return _build_report(normalized_selector, project, sessions, collector, effective)


# Discovery and selection ---------------------------------------------------


def _select_exact(
    session_id: str,
    claude_root: Path,
    codex_root: Path,
    limits: RecoveryLimits,
    collector: _Collector,
) -> list[SessionDescriptor]:
    canonical = _canonical_uuid(session_id)
    if canonical is None:
        collector.add_gap("selector", "invalid_session_id", "exact ID is not a UUID")
        return []
    candidates = _discover_sources(
        claude_root, codex_root, limits, collector, wanted_id=canonical
    )
    if not candidates:
        collector.add_gap(canonical, "session_not_found", "no session has the exact ID")
        return []
    candidates.sort(
        key=lambda item: (
            item.archived,
            -(item.mtime_ns if item.mtime_ns is not None else 0),
            item.provider,
            item.path,
        )
    )
    if len(candidates) > 1:
        collector.add_gap(
            canonical,
            "ambiguous_session_id",
            f"{len(candidates)} providers matched; selected the newest live session",
        )
    return [candidates[0]]


def _select_topic(
    topic: str,
    project_root: Path,
    claude_root: Path,
    codex_root: Path,
    limits: RecoveryLimits,
    collector: _Collector,
) -> list[SessionDescriptor]:
    candidates = _discover_sources(claude_root, codex_root, limits, collector)
    scored: list[SessionDescriptor] = []
    same_project = 0
    for descriptor in candidates:
        probe_limits = replace(
            limits,
            max_events=min(64, limits.max_events),
            max_output_chars=min(limits.max_topic_scan_bytes, limits.max_output_chars),
            max_evidence_gaps=min(32, limits.max_evidence_gaps),
            max_link_files=1,
        )
        probe_collector = _Collector(probe_limits)
        probed = _read_session(
            descriptor,
            probe_collector,
            probe_limits,
            byte_limit=limits.max_topic_scan_bytes,
            follow_links=False,
        )
        hints = {
            hint
            for hint in (
                descriptor.project_hint,
                probed.project_hint,
                *(_project_hints_from_events(probe_collector.events)),
            )
            if hint
        }
        if not _project_matches(project_root, descriptor, hints):
            continue
        same_project += 1
        corpus = "\n".join(event.content for event in probe_collector.events)
        score = _topic_score(topic, corpus)
        if score >= limits.topic_threshold:
            scored.append(replace(descriptor, topic_score=score))

    if same_project == 0:
        collector.add_gap(
            "selector", "project_no_sessions", "no discovered session matched the project"
        )
    elif not scored:
        collector.add_gap(
            "selector",
            "topic_no_high_confidence_match",
            f"no same-project session reached score {limits.topic_threshold:.2f}",
        )
        return []

    scored.sort(
        key=lambda item: (
            -(item.topic_score or 0.0),
            -(item.mtime_ns if item.mtime_ns is not None else 0),
            item.provider,
            item.path,
        )
    )
    if len(scored) > limits.max_sessions:
        collector.add_gap(
            "selector",
            "session_limit",
            f"topic matches bounded to {limits.max_sessions} sessions",
        )
        collector.truncated = True
    return scored[: limits.max_sessions]


def _discover_sources(
    claude_root: Path,
    codex_root: Path,
    limits: RecoveryLimits,
    collector: _Collector,
    *,
    wanted_id: str | None = None,
) -> list[SessionDescriptor]:
    found: list[SessionDescriptor] = []
    counter = [0]
    exhausted = [False]
    found.extend(
        _discover_claude(
            claude_root, limits, collector, counter, exhausted, wanted_id
        )
    )
    codex_found = _discover_codex(
        codex_root, limits, collector, counter, exhausted, wanted_id
    )
    found.extend(codex_found)

    unique: dict[tuple[str, str], SessionDescriptor] = {}
    for item in found:
        key = (item.provider, item.path)
        unique[key] = item
    result = list(unique.values())
    result.sort(
        key=lambda item: (
            -(item.mtime_ns if item.mtime_ns is not None else 0),
            item.provider,
            item.path,
        )
    )
    if wanted_id is None and len(result) > limits.max_candidates:
        result = result[: limits.max_candidates]
        collector.add_gap(
            "discovery",
            "candidate_limit",
            f"topic discovery bounded to {limits.max_candidates} newest sessions",
        )
        collector.truncated = True
    return result


def _discover_claude(
    root: Path,
    limits: RecoveryLimits,
    collector: _Collector,
    counter: list[int],
    exhausted: list[bool],
    wanted_id: str | None,
) -> list[SessionDescriptor]:
    result: list[SessionDescriptor] = []
    for project in _safe_scandir(root, collector, "Claude root"):
        if not _count_entry(counter, exhausted, limits, collector):
            break
        try:
            is_directory = project.is_dir(follow_symlinks=False)
        except OSError:
            continue
        if not is_directory:
            continue
        for entry in _safe_scandir(project.path, collector, "Claude project directory"):
            if not _count_entry(counter, exhausted, limits, collector):
                break
            session_id = _canonical_uuid(Path(entry.name).stem)
            if session_id is None or not entry.name.lower().endswith(".jsonl"):
                continue
            if wanted_id is not None and session_id != wanted_id:
                continue
            descriptor = _entry_descriptor(
                entry,
                provider="claude",
                session_id=session_id,
                archived=False,
                project_hint=project.name,
                source_root=root,
                limits=limits,
            )
            if descriptor is not None:
                result.append(descriptor)
    return result


def _discover_codex(
    root: Path,
    limits: RecoveryLimits,
    collector: _Collector,
    counter: list[int],
    exhausted: list[bool],
    wanted_id: str | None,
) -> list[SessionDescriptor]:
    if root.name.lower() == "sessions":
        sessions_root = root
        archive_root = root.parent / "archived_sessions"
    else:
        sessions_root = root / "sessions"
        archive_root = root / "archived_sessions"

    live: list[SessionDescriptor] = []
    live_ids: set[str] = set()
    years = _safe_scandir(sessions_root, collector, "Codex root")

    for year in years:
        if not _count_entry(counter, exhausted, limits, collector):
            break
        if not (year.name.isdigit() and len(year.name) == 4):
            continue
        for month in _safe_scandir(year.path, collector, "Codex year"):
            if not _count_entry(counter, exhausted, limits, collector):
                break
            if not (month.name.isdigit() and len(month.name) == 2):
                continue
            for day in _safe_scandir(month.path, collector, "Codex month"):
                if not _count_entry(counter, exhausted, limits, collector):
                    break
                if not (day.name.isdigit() and len(day.name) == 2):
                    continue
                for entry in _safe_scandir(day.path, collector, "Codex day"):
                    if not _count_entry(counter, exhausted, limits, collector):
                        break
                    session_id = _uuid_from_rollout_name(entry.name)
                    if session_id is None:
                        continue
                    if wanted_id is not None and session_id != wanted_id:
                        continue
                    descriptor = _entry_descriptor(
                        entry,
                        provider="codex",
                        session_id=session_id,
                        archived=False,
                        project_hint=None,
                        source_root=sessions_root,
                        limits=limits,
                    )
                    if descriptor is not None:
                        live.append(descriptor)
                        live_ids.add(session_id)

    archived: list[SessionDescriptor] = []
    for entry in _safe_scandir(archive_root, collector, "Codex archive"):
        if not _count_entry(counter, exhausted, limits, collector):
            break
        session_id = _uuid_from_rollout_name(entry.name)
        if session_id is None or session_id in live_ids:
            continue
        if wanted_id is not None and session_id != wanted_id:
            continue
        descriptor = _entry_descriptor(
            entry,
            provider="codex",
            session_id=session_id,
            archived=True,
            project_hint=None,
            source_root=archive_root,
            limits=limits,
        )
        if descriptor is not None:
            archived.append(descriptor)
    return live + archived


def _safe_scandir(
    path: str | os.PathLike[str], collector: _Collector, label: str
) -> Iterator[os.DirEntry[str]]:
    try:
        entries = os.scandir(path)
    except FileNotFoundError:
        return
    except NotADirectoryError:
        return
    except (OSError, DomainError) as exc:
        collector.add_gap("discovery", "discovery_error", f"{label}: {exc}")
        return
    try:
        with entries:
            yield from entries
    except (OSError, DomainError) as exc:
        collector.add_gap("discovery", "discovery_error", f"{label}: {exc}")


def _count_entry(
    counter: list[int],
    exhausted: list[bool],
    limits: RecoveryLimits,
    collector: _Collector,
) -> bool:
    counter[0] += 1
    if counter[0] <= limits.max_discovery_entries:
        return True
    if not exhausted[0]:
        exhausted[0] = True
        collector.add_gap(
            "discovery",
            "discovery_entry_limit",
            f"discovery stopped at {limits.max_discovery_entries} entries",
        )
        collector.truncated = True
    return False


def _entry_descriptor(
    entry: os.DirEntry[str],
    *,
    provider: str,
    session_id: str,
    archived: bool,
    project_hint: str | None,
    source_root: Path,
    limits: RecoveryLimits,
) -> SessionDescriptor | None:
    try:
        if not entry.is_file(follow_symlinks=False):
            return None
        info = entry.stat(follow_symlinks=False)
    except OSError:
        return None
    return SessionDescriptor(
        provider=provider,
        session_id=session_id,
        path=str(Path(os.path.abspath(entry.path))),
        archived=archived,
        project_hint=project_hint,
        mtime_ns=info.st_mtime_ns,
        source_root=str(Path(os.path.abspath(source_root))),
    )


# Descriptor-bound streaming ------------------------------------------------


def _read_session(
    descriptor: SessionDescriptor,
    collector: _Collector,
    limits: RecoveryLimits,
    *,
    byte_limit: int,
    follow_links: bool,
    force_session_id: str | None = None,
    source_artifact: str | None = None,
) -> SessionDescriptor:
    path = Path(descriptor.path)
    state = _ParseState(
        provider=descriptor.provider,
        session_id=force_session_id or descriptor.session_id,
        path=descriptor.path,
        force_session_id=force_session_id is not None,
    )
    links: list[_StructuredLink] = []
    source_root = Path(descriptor.source_root) if descriptor.source_root else path.parent
    try:
        handle = _open_readonly(path, source_root)
    except (OSError, DomainError) as exc:
        collector.add_gap(
            state.session_id,
            "unreadable_session",
            str(exc),
            path=descriptor.path,
        )
        return descriptor

    with handle:
        try:
            info = os.fstat(handle.fileno())
        except (OSError, DomainError) as exc:
            collector.add_gap(
                state.session_id,
                "snapshot_error",
                str(exc),
                path=descriptor.path,
            )
            return descriptor
        if not stat.S_ISREG(info.st_mode):
            collector.add_gap(
                state.session_id,
                "invalid_session_file",
                "source is not a regular file",
                path=descriptor.path,
            )
            return descriptor

        captured = info.st_size
        if captured == 0:
            collector.add_gap(
                state.session_id,
                "empty_session",
                "captured session is empty",
                path=descriptor.path,
            )
        for line_number, raw in _snapshot_lines(
            handle,
            captured,
            byte_limit,
            limits.max_line_bytes,
            state,
            collector,
        ):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                collector.add_gap(
                    state.session_id,
                    "invalid_utf8",
                    f"UTF-8 decoding failed at byte {exc.start}",
                    line=line_number,
                    path=source_artifact or descriptor.path,
                )
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                collector.add_gap(
                    state.session_id,
                    "malformed_json",
                    f"JSON decoding failed at column {exc.colno}",
                    line=line_number,
                    path=source_artifact or descriptor.path,
                )
                continue
            if not isinstance(record, Mapping):
                collector.add_gap(
                    state.session_id,
                    "invalid_record",
                    "JSONL record is not an object",
                    line=line_number,
                    path=source_artifact or descriptor.path,
                )
                continue
            events, record_links, invalid = _parse_record(
                record,
                state,
                line_number,
                limits,
                source_artifact=source_artifact,
            )
            if invalid:
                collector.add_gap(
                    state.session_id,
                    "invalid_record",
                    invalid,
                    line=line_number,
                    path=source_artifact or descriptor.path,
                )
            for event in events:
                collector.add_event(event)
            links.extend(record_links)

    project_hint = next(iter(sorted(state.project_hints)), descriptor.project_hint)
    if project_hint is not None:
        project_hint = _bounded_text(project_hint, limits.max_path_chars)
    updated = replace(
        descriptor,
        provider=state.provider,
        session_id=state.session_id,
        project_hint=project_hint,
        mtime_ns=info.st_mtime_ns,
        captured_size=captured,
    )
    if follow_links and source_artifact is None:
        _read_structured_links(updated, links, collector, limits)
    return updated


def _snapshot_lines(
    handle: Any,
    captured_size: int,
    byte_limit: int,
    max_line_bytes: int,
    state: _ParseState,
    collector: _Collector,
):
    scan_size = min(captured_size, byte_limit)
    position = 0
    line_number = 0
    short_snapshot = False
    while position < scan_size:
        line_number += 1
        remaining = scan_size - position
        part = handle.readline(min(max_line_bytes + 2, remaining))
        if not part:
            short_snapshot = True
            collector.add_gap(
                state.session_id,
                "snapshot_shrank",
                f"descriptor returned EOF at byte {position} of {captured_size}",
                line=line_number,
                path=state.path,
            )
            break
        position += len(part)
        if part.endswith(b"\n"):
            payload = part[:-1]
            if payload.endswith(b"\r"):
                payload = payload[:-1]
            if len(payload) > max_line_bytes:
                collector.add_gap(
                    state.session_id,
                    "oversized_line",
                    f"line exceeds {max_line_bytes} bytes",
                    line=line_number,
                    path=state.path,
                )
            else:
                yield line_number, payload
            continue

        # readline hit its bound while more snapshot bytes remain: consume the
        # rest of this oversized record without retaining it.
        if position < scan_size and len(part) >= max_line_bytes + 2:
            terminated = False
            while position < scan_size:
                chunk = handle.readline(min(64 * 1024, scan_size - position))
                if not chunk:
                    short_snapshot = True
                    break
                position += len(chunk)
                if chunk.endswith(b"\n"):
                    terminated = True
                    break
            collector.add_gap(
                state.session_id,
                "oversized_line",
                (
                    f"line exceeds {max_line_bytes} bytes"
                    if terminated
                    else f"unterminated line exceeds {max_line_bytes} bytes"
                ),
                line=line_number,
                path=state.path,
            )
            if short_snapshot:
                collector.add_gap(
                    state.session_id,
                    "snapshot_shrank",
                    f"descriptor returned EOF at byte {position} of {captured_size}",
                    line=line_number,
                    path=state.path,
                )
                break
            continue

        # At a configured scan boundary the fragment is omitted as a bounded
        # read, not misreported as corruption in the underlying session.
        if scan_size < captured_size:
            break
        if len(part) > max_line_bytes:
            kind = "oversized_line"
            detail = f"unterminated line exceeds {max_line_bytes} bytes"
        else:
            kind = "incomplete_line"
            detail = "captured snapshot ended before a newline"
        collector.add_gap(
            state.session_id,
            kind,
            detail,
            line=line_number,
            path=state.path,
        )

    if captured_size > scan_size:
        collector.add_gap(
            state.session_id,
            "session_byte_limit",
            f"read bounded to {scan_size} of {captured_size} captured bytes",
            path=state.path,
        )
        collector.truncated = True
    elif short_snapshot:
        collector.truncated = True


# Provider parsing ----------------------------------------------------------


def _parse_record(
    record: Mapping[str, Any],
    state: _ParseState,
    line_number: int,
    limits: RecoveryLimits,
    *,
    source_artifact: str | None,
) -> tuple[list[EvidenceEvent], list[_StructuredLink], str | None]:
    record_type = _normalized_name(record.get("type"))
    payload = record.get("payload")
    if isinstance(payload, Mapping):
        payload_type = _normalized_name(payload.get("type"))
    else:
        payload_type = ""

    if record_type in {"session_meta", "response_item", "event_msg", "turn_context"}:
        state.provider = "codex"
    elif record_type in {"assistant", "user"} and isinstance(record.get("message"), Mapping):
        state.provider = "claude"

    _update_parse_state(record, payload, state)
    timestamp = _first_string(record, "timestamp", "created_at", "time")
    event_id = _first_string(record, "uuid", "event_id")
    links: list[_StructuredLink] = []
    events: list[EvidenceEvent] = []

    if _is_sensitive_name(record_type) or _is_sensitive_name(payload_type):
        return events, links, None
    if record_type in {"session_meta", "turn_context", "token_count"}:
        return events, links, None

    if record_type in {"assistant", "user"}:
        message = record.get("message")
        if not isinstance(message, Mapping):
            return events, links, "message record has no message object"
        role = _normalized_role(message.get("role")) or record_type
        content = message.get("content")
        block_events, block_links = _events_from_content(
            content,
            state,
            role,
            timestamp,
            event_id,
            line_number,
            limits,
            origin="claude",
            source_artifact=source_artifact,
        )
        if content is None:
            return events, links, "message record has no content"
        return block_events, block_links, None

    if record_type == "event_msg":
        if not isinstance(payload, Mapping):
            return events, links, "event_msg has no payload object"
        if payload_type in {"agent_reasoning", "reasoning", "analysis"}:
            return events, links, None
        role_by_type = {
            "user_message": "user",
            "agent_message": "assistant",
            "assistant_message": "assistant",
        }
        if payload_type in role_by_type:
            value = payload.get("message", payload.get("text"))
            text = _render_visible(value, limits)
            if not text:
                return events, links, "message payload has no visible text"
            events.append(
                _make_event(
                    state,
                    kind="message",
                    role=role_by_type[payload_type],
                    content=text,
                    timestamp=timestamp,
                    event_id=event_id,
                    origin="codex_event",
                    source_artifact=source_artifact,
                )
            )
        elif payload_type in {"task_started", "task_complete", "task_completed", "turn_aborted"}:
            events.append(
                _make_event(
                    state,
                    kind="status",
                    role=None,
                    content=payload_type,
                    timestamp=timestamp,
                    event_id=event_id,
                    origin="codex_event",
                    source_artifact=source_artifact,
                )
            )
        return events, links, None

    if record_type == "response_item":
        if not isinstance(payload, Mapping):
            return events, links, "response_item has no payload object"
        if payload_type == "message":
            item_role = _normalized_role(payload.get("role"))
            block_events, block_links = _events_from_content(
                payload.get("content"),
                state,
                item_role,
                timestamp,
                event_id,
                line_number,
                limits,
                origin="codex_item",
                source_artifact=source_artifact,
            )
            if payload.get("content") is None:
                return events, links, "message item has no content"
            return block_events, block_links, None
        if payload_type in {"function_call", "custom_tool_call", "local_shell_call"}:
            name = _first_string(payload, "name", "tool_name") or payload_type
            call_id = _first_string(payload, "call_id", "id")
            arguments = payload.get("arguments", payload.get("input"))
            details = {"input": _parse_structured_string(arguments, limits)}
            events.append(
                _make_event(
                    state,
                    kind="tool_call",
                    role="assistant",
                    content=name,
                    timestamp=timestamp,
                    event_id=event_id,
                    tool_call_id=call_id,
                    details=details,
                    origin="codex_item",
                    source_artifact=source_artifact,
                )
            )
            return events, links, None
        if payload_type in {
            "function_call_output",
            "custom_tool_call_output",
            "local_shell_call_output",
        }:
            call_id = _first_string(payload, "call_id", "id")
            output = payload.get("output", payload.get("content"))
            text = _render_visible(output, limits)
            links.extend(_collect_structured_links(output, "tool_result", limits))
            if text:
                events.append(
                    _make_event(
                        state,
                        kind="tool_result",
                        role="tool",
                        content=text,
                        timestamp=timestamp,
                        event_id=event_id,
                        tool_call_id=call_id,
                        origin="codex_item",
                        source_artifact=source_artifact,
                    )
                )
            return events, links, None
        return events, links, None

    # A small generic form makes explicit fixture JSONL useful without weakening
    # provider-specific validation.
    if "role" in record and "content" in record:
        generic_role = _normalized_role(record.get("role"))
        generic_events, generic_links = _events_from_content(
            record.get("content"),
            state,
            generic_role,
            timestamp,
            event_id,
            line_number,
            limits,
            origin="generic",
            source_artifact=source_artifact,
        )
        return generic_events, generic_links, None

    if not record_type:
        return events, links, "record has no type"
    # Unknown typed records are valid forward-compatible metadata.
    return events, links, None


def _events_from_content(
    content: Any,
    state: _ParseState,
    role: str | None,
    timestamp: str | None,
    event_id: str | None,
    line_number: int,
    limits: RecoveryLimits,
    *,
    origin: str,
    source_artifact: str | None,
) -> tuple[list[EvidenceEvent], list[_StructuredLink]]:
    events: list[EvidenceEvent] = []
    links: list[_StructuredLink] = []
    blocks = content if isinstance(content, list) else [content]
    for index, block in enumerate(blocks):
        block_id = f"{event_id}:{index}" if event_id and len(blocks) > 1 else event_id
        if isinstance(block, str):
            text = _clean_visible_text(block)
            if text:
                events.append(
                    _make_event(
                        state,
                        kind="message",
                        role=role,
                        content=text,
                        timestamp=timestamp,
                        event_id=block_id,
                        origin=origin,
                        source_artifact=source_artifact,
                    )
                )
            continue
        if not isinstance(block, Mapping):
            continue
        block_type = _normalized_name(block.get("type"))
        if _is_sensitive_name(block_type):
            continue
        if block_type in {"text", "input_text", "output_text"} or (
            not block_type and "text" in block
        ):
            text = _render_visible(block.get("text", block.get("content")), limits)
            if text:
                events.append(
                    _make_event(
                        state,
                        kind="message",
                        role=role,
                        content=text,
                        timestamp=timestamp,
                        event_id=block_id,
                        origin=origin,
                        source_artifact=source_artifact,
                    )
                )
            continue
        if block_type in {"tool_use", "tool_call", "function_call"}:
            name = _first_string(block, "name", "tool_name") or "tool"
            call_id = _first_string(block, "id", "call_id")
            tool_input = block.get("input", block.get("arguments"))
            events.append(
                _make_event(
                    state,
                    kind="tool_call",
                    role="assistant",
                    content=name,
                    timestamp=timestamp,
                    event_id=block_id,
                    tool_call_id=call_id,
                    details={"input": _parse_structured_string(tool_input, limits)},
                    origin=origin,
                    source_artifact=source_artifact,
                )
            )
            continue
        if block_type in {"tool_result", "function_call_output", "tool_output"}:
            output = block.get("content", block.get("output"))
            call_id = _first_string(block, "tool_use_id", "call_id", "id")
            links.extend(_collect_structured_links(block, "tool_result", limits))
            text = _render_visible(output, limits)
            if text:
                events.append(
                    _make_event(
                        state,
                        kind="tool_result",
                        role="tool",
                        content=text,
                        timestamp=timestamp,
                        event_id=block_id,
                        tool_call_id=call_id,
                        origin=origin,
                        source_artifact=source_artifact,
                    )
                )
            continue
        if block_type in {"subagent", "agent_result", "agent_output"}:
            links.extend(_collect_structured_links(block, "subagent", limits))
            text = _render_visible(block.get("content", block.get("output")), limits)
            if text:
                events.append(
                    _make_event(
                        state,
                        kind="subagent_result",
                        role="tool",
                        content=text,
                        timestamp=timestamp,
                        event_id=block_id,
                        origin=origin,
                        source_artifact=source_artifact,
                    )
                )
    return events, links


def _make_event(
    state: _ParseState,
    *,
    kind: str,
    role: str | None,
    content: str,
    timestamp: str | None,
    event_id: str | None,
    origin: str,
    source_artifact: str | None,
    tool_call_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> EvidenceEvent:
    return EvidenceEvent(
        source_session=state.session_id,
        provider=state.provider,
        kind=kind,
        role=role,
        content=content,
        timestamp=_bounded_text(timestamp, 128) if timestamp else None,
        event_id=_bounded_text(event_id, 256) if event_id else None,
        tool_call_id=_bounded_text(tool_call_id, 256) if tool_call_id else None,
        details=details,
        source_artifact=source_artifact,
        origin=origin,
    )


def _update_parse_state(
    record: Mapping[str, Any], payload: Any, state: _ParseState
) -> None:
    if not state.force_session_id:
        possible_id = _first_string(record, "sessionId", "session_id")
        if _normalized_name(record.get("type")) == "session_meta" and isinstance(
            payload, Mapping
        ):
            possible_id = _first_string(payload, "id", "session_id") or possible_id
        if possible_id:
            state.session_id = _bounded_text(possible_id, 256)
    for source in (record, payload if isinstance(payload, Mapping) else None):
        if not isinstance(source, Mapping):
            continue
        for key in ("cwd", "project_root", "project_path", "workspace"):
            value = source.get(key)
            if isinstance(value, str) and value:
                state.project_hints.add(value)


# Structured linked artifacts ---------------------------------------------


def _collect_structured_links(
    value: Any, context: str, limits: RecoveryLimits
) -> list[_StructuredLink]:
    result: list[_StructuredLink] = []
    seen: set[tuple[str, str]] = set()

    def visit(node: Any, inherited: str, depth: int, structured: bool = False) -> None:
        if depth > limits.max_structured_depth or len(result) >= limits.max_link_files * 4:
            return
        if isinstance(node, Mapping):
            signal = _normalized_name(node.get("kind", node.get("type")))
            signaled_kind = inherited
            if "subagent" in signal or signal in {"agent_result", "agent_output"}:
                signaled_kind = "subagent"
            elif "tool_result" in signal or signal in {"tool_output", "result"}:
                signaled_kind = "tool_result"
            if structured and isinstance(node.get("path"), str):
                add(node["path"], signaled_kind)
            elif signaled_kind in {"subagent", "tool_result"} and isinstance(
                node.get("path"), str
            ):
                add(node["path"], signaled_kind)
            for key, child in list(node.items())[: limits.max_structured_items]:
                normalized = _normalized_name(key)
                if normalized in _LINK_KEYS and isinstance(child, str):
                    add(child, _LINK_KEYS[normalized])
                elif normalized in {"structured_link", "structured_links", "links"}:
                    visit(child, signaled_kind, depth + 1, True)
                elif isinstance(child, (Mapping, list, tuple)):
                    visit(child, signaled_kind, depth + 1, structured)
        elif isinstance(node, (list, tuple)):
            for child in list(node)[: limits.max_structured_items]:
                visit(child, inherited, depth + 1, structured)

    def add(path: str, kind: str) -> None:
        cleaned = path.strip()
        if not cleaned:
            return
        key = (cleaned, kind)
        if key not in seen:
            seen.add(key)
            result.append(_StructuredLink(cleaned, kind))

    visit(value, context, 0)
    return result


def _read_structured_links(
    descriptor: SessionDescriptor,
    links: list[_StructuredLink],
    collector: _Collector,
    limits: RecoveryLimits,
) -> None:
    artifact_root = Path(descriptor.path).parent / descriptor.session_id
    if not artifact_root.is_dir():
        if links:
            collector.add_gap(
                descriptor.session_id,
                "linked_root_missing",
                "structured linked files have no verified session artifact root",
                path=descriptor.path,
            )
        return
    seen: set[str] = set()
    for link in links:
        if len(seen) >= limits.max_link_files:
            collector.add_gap(
                descriptor.session_id,
                "linked_file_limit",
                f"structured links bounded to {limits.max_link_files} files",
                path=descriptor.path,
            )
            collector.truncated = True
            break
        resolved = _resolve_link_path(link.path, Path(descriptor.path).parent)
        rendered_path = _bounded_text(str(resolved), limits.max_path_chars)
        if not _is_path_within(resolved, artifact_root):
            collector.add_gap(
                descriptor.session_id,
                "linked_file_outside_session",
                "structured link is outside the verified session artifact root",
                path=rendered_path,
            )
            continue
        identity = os.path.normcase(os.path.abspath(resolved))
        if identity in seen:
            continue
        seen.add(identity)
        try:
            suffix = resolved.suffix.lower()
            if suffix == ".jsonl":
                linked_descriptor = SessionDescriptor(
                    provider=descriptor.provider,
                    session_id=descriptor.session_id,
                    path=str(resolved),
                    source_root=str(artifact_root),
                )
                parsed = _read_session(
                    linked_descriptor,
                    collector,
                    limits,
                    byte_limit=limits.max_link_bytes,
                    follow_links=False,
                    force_session_id=descriptor.session_id,
                    source_artifact=rendered_path,
                )
                collector.linked_sources.append(
                    {
                        "source_session": descriptor.session_id,
                        "kind": link.kind,
                        "path": rendered_path,
                        "captured_size": parsed.captured_size,
                    }
                )
            else:
                captured = _read_plain_link(
                    resolved,
                    artifact_root,
                    rendered_path,
                    link.kind,
                    descriptor,
                    collector,
                    limits,
                )
                collector.linked_sources.append(
                    {
                        "source_session": descriptor.session_id,
                        "kind": link.kind,
                        "path": rendered_path,
                        "captured_size": captured,
                    }
                )
        except (OSError, DomainError) as exc:
            collector.add_gap(
                descriptor.session_id,
                "linked_file_unreadable",
                str(exc),
                path=rendered_path,
            )


def _read_plain_link(
    path: Path,
    root: Path,
    rendered_path: str,
    link_kind: str,
    descriptor: SessionDescriptor,
    collector: _Collector,
    limits: RecoveryLimits,
) -> int | None:
    handle = _open_readonly(path, root)
    with handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError("structured link is not a regular file")
        captured = info.st_size
        state = _ParseState(
            descriptor.provider,
            descriptor.session_id,
            rendered_path,
            force_session_id=True,
        )
        for line_number, raw in _snapshot_lines(
            handle,
            captured,
            limits.max_link_bytes,
            limits.max_line_bytes,
            state,
            collector,
        ):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                collector.add_gap(
                    descriptor.session_id,
                    "invalid_utf8",
                    f"linked UTF-8 decoding failed at byte {exc.start}",
                    line=line_number,
                    path=rendered_path,
                )
                continue
            visible = _visible_plain_link_line(text, limits)
            if visible:
                collector.add_event(
                    EvidenceEvent(
                        source_session=descriptor.session_id,
                        provider=descriptor.provider,
                        kind=(
                            "subagent_result"
                            if link_kind == "subagent"
                            else "tool_result"
                        ),
                        role="tool",
                        content=visible,
                        source_artifact=rendered_path,
                        origin="linked_file",
                    )
                )
        return captured


def _visible_plain_link_line(text: str, limits: RecoveryLimits) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return _clean_visible_text(stripped)
    sanitized = _sanitize_structured(parsed, limits)
    if sanitized in (None, {}, []):
        return ""
    if isinstance(sanitized, str):
        return _clean_visible_text(sanitized)
    return _json_compact(sanitized)


# Sanitization and utility helpers -----------------------------------------


def _sanitize_structured(
    value: Any, limits: RecoveryLimits, depth: int = 0
) -> Any:
    if depth > limits.max_structured_depth:
        return "<depth-limit>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _bounded_text(_clean_visible_text(value), limits.max_event_chars)
    if isinstance(value, Mapping):
        value_type = _normalized_name(value.get("type"))
        if _is_sensitive_name(value_type):
            return None
        mapping_result: dict[str, Any] = {}
        for key, child in list(value.items())[: limits.max_structured_items]:
            normalized = _normalized_name(key)
            if _is_sensitive_name(normalized):
                continue
            cleaned = _sanitize_structured(child, limits, depth + 1)
            if cleaned is not None:
                mapping_result[_bounded_text(str(key), 128)] = cleaned
        return mapping_result
    if isinstance(value, (list, tuple)):
        sequence_result: list[Any] = []
        for child in list(value)[: limits.max_structured_items]:
            cleaned = _sanitize_structured(child, limits, depth + 1)
            if cleaned is not None:
                sequence_result.append(cleaned)
        return sequence_result
    return _bounded_text(str(value), limits.max_event_chars)


def _render_visible(value: Any, limits: RecoveryLimits) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                pass
            else:
                if isinstance(parsed, (Mapping, list)):
                    sanitized = _sanitize_structured(parsed, limits)
                    if sanitized in (None, {}, []):
                        return ""
                    return _json_compact(sanitized)
        return _clean_visible_text(value)
    if isinstance(value, (list, tuple)):
        visible = [_render_visible(item, limits) for item in value]
        return "\n".join(item for item in visible if item)
    if isinstance(value, Mapping):
        value_type = _normalized_name(value.get("type"))
        if _is_sensitive_name(value_type):
            return ""
        for key in ("text", "output_text", "input_text", "message", "content"):
            if key in value:
                rendered = _render_visible(value[key], limits)
                if rendered:
                    return rendered
        sanitized = _sanitize_structured(value, limits)
        return _json_compact(sanitized) if sanitized not in (None, {}, []) else ""
    return _clean_visible_text(str(value))


def _parse_structured_string(value: Any, limits: RecoveryLimits) -> Any:
    if not isinstance(value, str):
        return _sanitize_structured(value, limits)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return _bounded_text(_clean_visible_text(value), limits.max_event_chars)
    return _sanitize_structured(parsed, limits)


def _clean_visible_text(value: str) -> str:
    cleaned = value.replace("\x00", "")
    previous = None
    while previous != cleaned:
        previous = cleaned
        cleaned = _SENSITIVE_TAG_RE.sub("", cleaned)
    cleaned = _SENSITIVE_LINE_RE.sub("", cleaned)
    return cleaned.strip()


def _is_sensitive_name(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", value.casefold())
    if value in _SENSITIVE_NAMES or compact in {
        "analysis",
        "chainofthought",
        "encrypted",
        "encryptedcontent",
        "reasoning",
        "reasoningcontent",
        "redactedreasoning",
        "redactedthinking",
        "signature",
        "thinking",
        "thinkingcontent",
    }:
        return True
    return any(
        marker in compact
        for marker in (
            "analysis",
            "chainofthought",
            "encrypted",
            "reasoning",
            "signature",
            "thinking",
        )
    )


def _topic_score(topic: str, corpus: str) -> float:
    query_tokens = _topic_tokens(topic)
    if not query_tokens or not corpus:
        return 0.0
    corpus_folded = corpus.casefold()
    corpus_tokens = _topic_tokens(corpus)
    matched = sum(1 for token in query_tokens if token in corpus_tokens)
    coverage = matched / len(query_tokens)
    normalized_topic = " ".join(topic.casefold().split())
    normalized_corpus = " ".join(corpus_folded.split())
    phrase = 1.0 if normalized_topic and normalized_topic in normalized_corpus else 0.0
    return min(1.0, coverage * 0.90 + phrase * 0.10)


def _topic_tokens(value: str) -> set[str]:
    folded = value.casefold()
    result = {
        token
        for token in _WORD_RE.findall(folded)
        if token not in _STOP_WORDS and len(token) > 1
    }
    for run in _CJK_RE.findall(folded):
        if len(run) <= 4:
            result.add(run)
        if len(run) > 1:
            result.update(run[index : index + 2] for index in range(len(run) - 1))
    return result


def _project_matches(
    project_root: Path,
    descriptor: SessionDescriptor,
    hints: set[str],
) -> bool:
    project_key = _path_key(project_root)
    for hint in hints:
        try:
            hint_path = _absolute_path(hint, None)
            hint_key = _path_key(hint_path)
            if hint_key == project_key or _is_path_within(hint_path, project_root):
                return True
        except (OSError, ValueError):
            continue
    if descriptor.provider == "claude" and descriptor.project_hint:
        variants = _claude_project_variants(project_root)
        return descriptor.project_hint.casefold() in variants
    return False


def _project_hints_from_events(events: list[EvidenceEvent]) -> set[str]:
    # Project hints are extracted in parse state.  This helper intentionally does
    # not mine visible text for paths: natural-language paths are not authority.
    return set()


def _claude_project_variants(project_root: Path) -> set[str]:
    raw = str(project_root)
    replaced = raw.replace("\\", "-").replace("/", "-").replace(":", "-")
    compact = re.sub(r"[^A-Za-z0-9_-]", "-", raw)
    return {
        replaced.casefold(),
        compact.casefold(),
        replaced.lstrip("-").casefold(),
        compact.lstrip("-").casefold(),
    }


def _sort_events(
    events: list[EvidenceEvent], sessions: list[SessionDescriptor]
) -> None:
    mtimes = {
        item.session_id: (item.mtime_ns or 0) / 1_000_000_000 for item in sessions
    }

    def key(event: EvidenceEvent) -> tuple[float, int, str]:
        parsed = _timestamp_value(event.timestamp)
        if parsed is None:
            parsed = mtimes.get(event.source_session, 0.0)
        return parsed, event.sequence, event.source_session

    events.sort(key=key)
    for sequence, event in enumerate(events):
        event.sequence = sequence


def _timestamp_value(value: str | None) -> float | None:
    if not value:
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _build_report(
    selector: SessionSelector,
    project_root: Path,
    sessions: list[SessionDescriptor],
    collector: _Collector,
    limits: RecoveryLimits,
) -> dict[str, Any]:
    selector_limit = (
        limits.max_path_chars if selector.kind == "path" else limits.max_event_chars
    )
    return {
        "schema_version": 1,
        "mode": "report_only",
        "selector": {
            "kind": selector.kind,
            "value": _bounded_text(selector.value, selector_limit),
        },
        "project_root": _bounded_text(str(project_root), limits.max_path_chars),
        "sessions": [_bounded_descriptor(item, limits) for item in sessions],
        "events": [event.to_dict() for event in collector.events],
        "evidence_gaps": [gap.to_dict() for gap in collector.gaps],
        "linked_sources": list(collector.linked_sources),
        "truncated": collector.truncated,
        "stats": {
            "sessions": len(sessions),
            "events": len(collector.events),
            "evidence_gaps": len(collector.gaps),
            "linked_sources": len(collector.linked_sources),
            "visible_characters": collector.char_count,
        },
    }


def _bounded_descriptor(
    descriptor: SessionDescriptor, limits: RecoveryLimits
) -> dict[str, Any]:
    result = descriptor.to_dict()
    result["path"] = _bounded_text(descriptor.path, limits.max_path_chars)
    if descriptor.project_hint is not None:
        result["project_hint"] = _bounded_text(
            descriptor.project_hint, limits.max_path_chars
        )
    return result


def _codex_allowed_roots(codex_root: Path) -> tuple[Path, Path]:
    if codex_root.name.casefold() == "sessions":
        return codex_root, codex_root.parent / "archived_sessions"
    return codex_root / "sessions", codex_root / "archived_sessions"


def _allowed_explicit_root(
    path: Path, project_root: Path, claude_root: Path, codex_root: Path
) -> Path | None:
    roots = (project_root, claude_root, *_codex_allowed_roots(codex_root))
    for root in roots:
        if root.is_dir() and _is_path_within(path, root):
            return root
    return None


def _descriptor_for_path(
    path: Path, limits: RecoveryLimits, source_root: Path
) -> SessionDescriptor:
    session_id = _session_id_from_name(path.name) or _bounded_text(path.stem, 256)
    mtime_ns: int | None = None
    try:
        mtime_ns = path.stat().st_mtime_ns
    except OSError:
        pass
    return SessionDescriptor(
        provider=_infer_provider(path),
        session_id=session_id or "explicit-path",
        path=str(path),
        archived="archived_sessions" in {part.lower() for part in path.parts},
        mtime_ns=mtime_ns,
        source_root=str(Path(os.path.abspath(source_root))),
    )


def _infer_provider(path: Path) -> str:
    lowered = {part.lower() for part in path.parts}
    if ".codex" in lowered or path.name.lower().startswith("rollout-"):
        return "codex"
    if ".claude" in lowered:
        return "claude"
    return "unknown"


def _session_id_from_name(name: str) -> str | None:
    matches = _UUID_RE.findall(name)
    return _canonical_uuid(matches[-1]) if matches else None


def _uuid_from_rollout_name(name: str) -> str | None:
    if not (name.lower().startswith("rollout-") and name.lower().endswith(".jsonl")):
        return None
    return _session_id_from_name(name)


def _canonical_uuid(value: str) -> str | None:
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _looks_like_path(value: str) -> bool:
    if value.lower().startswith("file://"):
        return True
    if value.lower().endswith(".jsonl"):
        return True
    if value.startswith(("./", "../", "~/", ".\\", "..\\", "~\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    return os.sep in value or (os.altsep is not None and os.altsep in value)


def _absolute_path(value: str, home: Path | None) -> Path:
    raw = value.strip()
    if raw.lower().startswith("file://"):
        parsed = urlparse(raw)
        raw = unquote(parsed.path)
        if parsed.netloc and parsed.netloc not in {"", "localhost"}:
            raw = f"//{parsed.netloc}{raw}"
        elif re.match(r"^/[A-Za-z]:/", raw):
            raw = raw[1:]
    if home is not None and (raw == "~" or raw.startswith(("~/", "~\\"))):
        suffix = raw[2:] if len(raw) > 1 else ""
        path = home / suffix
    else:
        path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return Path(os.path.abspath(path))


def _resolve_link_path(value: str, parent: Path) -> Path:
    if value.lower().startswith("file://"):
        return _absolute_path(value, None)
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = parent / path
    return Path(os.path.abspath(path))


def _open_readonly(path: Path, root: Path):
    return open_verified_readonly(path, root, reject_hardlinks=True)


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.realpath(path))


def _is_path_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([_path_key(path), _path_key(root)]) == _path_key(root)
    except ValueError:
        return False


def _normalized_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().casefold().replace("-", "_").replace(" ", "_")


def _normalized_role(value: Any) -> str | None:
    role = _normalized_name(value)
    if role in {"user", "assistant", "system", "tool", "developer"}:
        return role
    return role or None


def _first_string(mapping: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _bounded_text(value: Any, limit: int) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _json_compact(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return ""
