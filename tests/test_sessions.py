from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from session_continuity import sessions as sessions_module  # noqa: E402
from session_continuity.sessions import reconstruct  # noqa: E402


class SessionRecoveryTests(unittest.TestCase):
    CLAUDE_ONE = "11111111-1111-4111-8111-111111111111"
    CLAUDE_TWO = "22222222-2222-4222-8222-222222222222"
    CLAUDE_THREE = "33333333-3333-4333-8333-333333333333"
    CODEX_ONE = "44444444-4444-4444-8444-444444444444"
    CODEX_TWO = "55555555-5555-4555-8555-555555555555"
    SHARED_EVENT = "99999999-9999-4999-8999-999999999999"

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "workspace" / "synthetic-project"
        self.project.mkdir(parents=True)
        self.claude_root = self.root / ".claude" / "projects"
        self.claude_root.mkdir(parents=True)
        self.codex_root = self.root / ".codex"
        self.codex_root.mkdir(parents=True)

    def _write_jsonl(
        self,
        path: Path,
        records: list[object],
        *,
        final_newline: bool = True,
    ) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = [
            json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            for record in records
        ]
        payload = b"\n".join(encoded)
        if final_newline and encoded:
            payload += b"\n"
        path.write_bytes(payload)
        return path

    def _claude_session(self, session_id: str, records: list[object]) -> Path:
        return self._write_jsonl(
            self.claude_root / "synthetic-project-key" / f"{session_id}.jsonl",
            records,
        )

    def _codex_meta(self, session_id: str, project: Path | None = None) -> dict[str, object]:
        return {
            "timestamp": "2026-01-01T00:00:00Z",
            "type": "session_meta",
            "payload": {
                "type": "session_meta",
                "id": session_id,
                "cwd": str(project or self.project),
            },
        }

    def _codex_live(self, session_id: str, records: list[object]) -> Path:
        return self._write_jsonl(
            self.codex_root
            / "sessions"
            / "2026"
            / "01"
            / "02"
            / f"rollout-synthetic-{session_id}.jsonl",
            records,
        )

    def _codex_archive(self, session_id: str, records: list[object]) -> Path:
        return self._write_jsonl(
            self.codex_root
            / "archived_sessions"
            / f"rollout-archived-{session_id}.jsonl",
            records,
        )

    def _reconstruct(self, selector: object, **overrides: object) -> dict[str, object]:
        return reconstruct(
            selector,
            self.project,
            home=self.root,
            claude_root=self.claude_root,
            codex_root=self.codex_root,
            **overrides,
        )

    def _claude_message(
        self,
        content: str,
        *,
        timestamp: str = "2026-01-01T00:00:00Z",
        event_id: str | None = None,
        project: Path | None = None,
        role: str = "user",
    ) -> dict[str, object]:
        record: dict[str, object] = {
            "timestamp": timestamp,
            "type": role,
            "cwd": str(project or self.project),
            "message": {"role": role, "content": content},
        }
        if event_id is not None:
            record["uuid"] = event_id
        return record

    def _tree_state(self) -> dict[str, tuple[object, ...]]:
        state: dict[str, tuple[object, ...]] = {}
        for path in sorted(self.root.rglob("*"), key=lambda item: str(item)):
            relative = path.relative_to(self.root).as_posix()
            if path.is_dir():
                state[relative] = ("directory",)
            else:
                state[relative] = ("file", path.read_bytes(), path.stat().st_mtime_ns)
        return state

    def test_path_selector_reads_direct_claude_uuid_jsonl(self) -> None:
        path = self._claude_session(
            self.CLAUDE_ONE,
            [self._claude_message("path selector marker")],
        )

        report = self._reconstruct(path)

        self.assertEqual(report["selector"]["kind"], "path")
        self.assertEqual(report["sessions"][0]["session_id"], self.CLAUDE_ONE)
        self.assertEqual(report["sessions"][0]["provider"], "claude")
        self.assertEqual(report["events"][0]["content"], "path selector marker")

    def test_exact_uuid_selects_only_matching_claude_session(self) -> None:
        self._claude_session(
            self.CLAUDE_ONE,
            [self._claude_message("exact identifier marker")],
        )
        self._claude_session(
            self.CLAUDE_TWO,
            [self._claude_message("nonmatching identifier marker")],
        )

        report = self._reconstruct(self.CLAUDE_ONE)

        self.assertEqual(report["selector"], {"kind": "id", "value": self.CLAUDE_ONE})
        self.assertEqual([item["session_id"] for item in report["sessions"]], [self.CLAUDE_ONE])
        self.assertEqual(
            [event["content"] for event in report["events"]],
            ["exact identifier marker"],
        )

    def test_topic_selection_is_same_project_and_bounded_to_newest_matches(self) -> None:
        first = self._claude_session(
            self.CLAUDE_ONE,
            [self._claude_message("alpha bridge first marker")],
        )
        second = self._claude_session(
            self.CLAUDE_TWO,
            [self._claude_message("alpha bridge second marker")],
        )
        third = self._codex_live(
            self.CODEX_ONE,
            [
                self._codex_meta(self.CODEX_ONE),
                {
                    "timestamp": "2026-01-01T00:00:03Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "user_message",
                        "message": "alpha bridge third marker",
                    },
                },
            ],
        )
        foreign_project = self.root / "workspace" / "foreign-project"
        self._codex_live(
            self.CODEX_TWO,
            [
                self._codex_meta(self.CODEX_TWO, foreign_project),
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "user_message",
                        "message": "alpha bridge foreign marker",
                    },
                },
            ],
        )
        base = time.time_ns() - 10_000_000_000
        for offset, path in enumerate((first, second, third), start=1):
            stamp = base + offset * 1_000_000_000
            os.utime(path, ns=(stamp, stamp))

        report = self._reconstruct(
            "topic:alpha bridge",
            max_sessions=2,
            topic_threshold=0.9,
        )

        self.assertEqual(
            [item["session_id"] for item in report["sessions"]],
            [self.CODEX_ONE, self.CLAUDE_TWO],
        )
        self.assertNotIn(
            "alpha bridge foreign marker",
            [event["content"] for event in report["events"]],
        )
        self.assertIn("session_limit", {gap["kind"] for gap in report["evidence_gaps"]})
        self.assertTrue(report["truncated"])
        self.assertEqual(report["stats"]["sessions"], 2)

    def test_codex_live_rollout_precedes_archive_with_same_uuid(self) -> None:
        self._codex_archive(
            self.CODEX_ONE,
            [
                self._codex_meta(self.CODEX_ONE),
                {
                    "type": "event_msg",
                    "payload": {"type": "user_message", "message": "archive marker"},
                },
            ],
        )
        live = self._codex_live(
            self.CODEX_ONE,
            [
                self._codex_meta(self.CODEX_ONE),
                {
                    "type": "event_msg",
                    "payload": {"type": "user_message", "message": "live marker"},
                },
            ],
        )

        report = self._reconstruct(f"id:{self.CODEX_ONE}")

        self.assertEqual(len(report["sessions"]), 1)
        self.assertFalse(report["sessions"][0]["archived"])
        self.assertEqual(Path(report["sessions"][0]["path"]), live)
        self.assertEqual([event["content"] for event in report["events"]], ["live marker"])

    def test_sources_merge_chronologically_with_provider_tags_and_dedupe(self) -> None:
        claude = self._claude_session(
            self.CLAUDE_ONE,
            [
                self._claude_message(
                    "merge topic shared marker",
                    timestamp="2026-01-01T00:00:00Z",
                    event_id=self.SHARED_EVENT,
                ),
                self._claude_message(
                    "merge topic claude marker",
                    timestamp="2026-01-01T00:00:02Z",
                    role="assistant",
                ),
            ],
        )
        codex = self._codex_live(
            self.CODEX_ONE,
            [
                self._codex_meta(self.CODEX_ONE),
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "uuid": self.SHARED_EVENT,
                    "type": "event_msg",
                    "payload": {
                        "type": "user_message",
                        "message": "merge topic shared marker",
                    },
                },
                {
                    "timestamp": "2026-01-01T00:00:01Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "agent_message",
                        "message": "merge topic codex marker",
                    },
                },
                {
                    "timestamp": "2026-01-01T00:00:03Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "agent_message",
                        "message": "merge topic wrapper marker",
                    },
                },
                {
                    "timestamp": "2026-01-01T00:00:03Z",
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": "merge topic wrapper marker"}
                        ],
                    },
                },
            ],
        )
        base = time.time_ns() - 5_000_000_000
        os.utime(claude, ns=(base, base))
        os.utime(codex, ns=(base + 1_000_000_000, base + 1_000_000_000))

        report = self._reconstruct("topic:merge topic", topic_threshold=0.9)

        contents = [event["content"] for event in report["events"]]
        self.assertEqual(
            contents,
            [
                "merge topic shared marker",
                "merge topic codex marker",
                "merge topic claude marker",
                "merge topic wrapper marker",
            ],
        )
        self.assertEqual(contents.count("merge topic wrapper marker"), 1)
        shared = report["events"][0]
        self.assertEqual(shared["source_session"], self.CLAUDE_ONE)
        self.assertEqual(shared["provider"], "claude")
        self.assertEqual(shared["also_seen_in"], [self.CODEX_ONE])
        codex_event = next(
            event for event in report["events"] if event["content"] == "merge topic codex marker"
        )
        self.assertEqual(codex_event["source_session"], self.CODEX_ONE)
        self.assertEqual(codex_event["provider"], "codex")
        self.assertEqual([event["sequence"] for event in report["events"]], list(range(4)))

    def test_bad_jsonl_records_are_reported_as_evidence_gaps(self) -> None:
        path = self.claude_root / "synthetic-project-key" / f"{self.CLAUDE_ONE}.jsonl"
        path.parent.mkdir(parents=True)
        lines = [
            json.dumps({"role": "user", "content": "valid gap marker"}).encode() + b"\n",
            b'{"type":invalid}\n',
            b"[]\n",
            b"\xff\n",
            json.dumps({"type": "user", "message": {}}).encode() + b"\n",
            json.dumps({"role": "user", "content": "X" * 200}).encode() + b"\n",
            json.dumps({"role": "assistant", "content": "incomplete marker"}).encode(),
        ]
        path.write_bytes(b"".join(lines))

        report = self._reconstruct(path, max_line_bytes=96)

        kinds = {gap["kind"] for gap in report["evidence_gaps"]}
        self.assertTrue(
            {"malformed_json", "invalid_record", "invalid_utf8", "oversized_line", "incomplete_line"}
            <= kinds
        )
        self.assertEqual([event["content"] for event in report["events"]], ["valid gap marker"])
        self.assertNotIn("incomplete marker", json.dumps(report, ensure_ascii=False))

    def test_active_append_is_excluded_after_descriptor_snapshot(self) -> None:
        path = self._claude_session(
            self.CLAUDE_ONE,
            [{"role": "user", "content": "snapshot marker"}],
        )
        captured_size = path.stat().st_size
        appended = json.dumps(
            {"role": "assistant", "content": "late append marker"},
            separators=(",", ":"),
        ).encode() + b"\n"
        original_snapshot_lines = sessions_module._snapshot_lines
        append_count = 0

        def append_then_read(
            handle: object,
            size: int,
            byte_limit: int,
            max_line_bytes: int,
            state: object,
            collector: object,
        ):
            nonlocal append_count
            if append_count == 0:
                self.assertEqual(size, captured_size)
                with path.open("ab") as writer:
                    writer.write(appended)
                    writer.flush()
                append_count += 1
            yield from original_snapshot_lines(
                handle,
                size,
                byte_limit,
                max_line_bytes,
                state,
                collector,
            )

        with mock.patch.object(sessions_module, "_snapshot_lines", append_then_read):
            report = self._reconstruct(path)

        self.assertEqual(append_count, 1)
        self.assertGreater(path.stat().st_size, captured_size)
        self.assertEqual(report["sessions"][0]["captured_size"], captured_size)
        self.assertEqual([event["content"] for event in report["events"]], ["snapshot marker"])
        self.assertNotIn("late append marker", json.dumps(report, ensure_ascii=False))

    def test_sensitive_reasoning_fields_blocks_and_text_are_suppressed(self) -> None:
        hidden_markers = {
            "HIDDEN_BLOCK",
            "HIDDEN_CODEX_EVENT",
            "HIDDEN_CODEX_ITEM",
            "HIDDEN_TAG",
            "HIDDEN_LINE",
            "HIDDEN_ARGUMENT",
        }
        path = self._claude_session(
            self.CLAUDE_ONE,
            [
                {
                    "type": "assistant",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "thinking", "thinking": "HIDDEN_BLOCK"},
                            {"type": "text", "text": "visible block marker"},
                        ],
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {"type": "agent_reasoning", "text": "HIDDEN_CODEX_EVENT"},
                },
                {
                    "type": "response_item",
                    "payload": {"type": "reasoning", "summary": "HIDDEN_CODEX_ITEM"},
                },
                {
                    "role": "assistant",
                    "content": (
                        "<thinking>HIDDEN_TAG</thinking>\n"
                        "visible plain marker\n"
                        "reasoning: HIDDEN_LINE"
                    ),
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "synthetic_tool",
                        "call_id": "call-1",
                        "arguments": json.dumps(
                            {
                                "reasoning": "HIDDEN_ARGUMENT",
                                "value": "visible input marker",
                            }
                        ),
                    },
                },
            ],
        )

        report = self._reconstruct(path)
        rendered = json.dumps(report, ensure_ascii=False)

        for marker in hidden_markers:
            self.assertNotIn(marker, rendered)
        self.assertIn("visible block marker", rendered)
        self.assertIn("visible plain marker", rendered)
        self.assertIn("visible input marker", rendered)

    def test_structured_links_are_read_only_within_session_artifact_root(self) -> None:
        session_path = self.claude_root / "synthetic-project-key" / f"{self.CLAUDE_ONE}.jsonl"
        artifact_root = session_path.parent / self.CLAUDE_ONE
        linked_jsonl = self._write_jsonl(
            artifact_root / "tool-result.jsonl",
            [{"role": "tool", "content": "contained tool marker"}],
        )
        linked_text = artifact_root / "subagent-result.txt"
        linked_text.write_text(
            json.dumps(
                {"message": "contained subagent marker", "reasoning": "HIDDEN_LINK_REASONING"}
            )
            + "\n",
            encoding="utf-8",
        )
        self._write_jsonl(
            session_path,
            [
                {
                    "type": "assistant",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "call-1",
                                "content": {
                                    "status": "synthetic result",
                                    "output_path": f"{self.CLAUDE_ONE}/{linked_jsonl.name}",
                                },
                            },
                            {
                                "type": "agent_result",
                                "content": "synthetic subagent result",
                                "transcript_path": f"{self.CLAUDE_ONE}/{linked_text.name}",
                            },
                        ],
                    },
                }
            ],
        )

        report = self._reconstruct(session_path)
        rendered = json.dumps(report, ensure_ascii=False)

        self.assertEqual(report["stats"]["linked_sources"], 2)
        self.assertEqual(
            {source["kind"] for source in report["linked_sources"]},
            {"tool_result", "subagent"},
        )
        for source in report["linked_sources"]:
            self.assertTrue(Path(source["path"]).resolve().is_relative_to(artifact_root.resolve()))
        self.assertIn("contained tool marker", rendered)
        self.assertIn("contained subagent marker", rendered)
        self.assertNotIn("HIDDEN_LINK_REASONING", rendered)
        linked_events = [event for event in report["events"] if "source_artifact" in event]
        self.assertEqual({event["source_session"] for event in linked_events}, {self.CLAUDE_ONE})

    def test_structured_link_traversal_is_an_evidence_gap_without_escape_read(self) -> None:
        session_path = self.claude_root / "synthetic-project-key" / f"{self.CLAUDE_ONE}.jsonl"
        artifact_root = session_path.parent / self.CLAUDE_ONE
        artifact_root.mkdir(parents=True)
        escaped = self._write_jsonl(
            session_path.parent / "escaped.jsonl",
            [{"role": "tool", "content": "escaped payload marker"}],
        )
        self._write_jsonl(
            session_path,
            [
                {
                    "type": "assistant",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_result",
                                "content": {
                                    "status": "synthetic result",
                                    "output_path": f"{self.CLAUDE_ONE}/../{escaped.name}",
                                },
                            }
                        ],
                    },
                }
            ],
        )

        report = self._reconstruct(session_path)
        rendered = json.dumps(report, ensure_ascii=False)

        self.assertIn(
            "linked_file_outside_session",
            {gap["kind"] for gap in report["evidence_gaps"]},
        )
        self.assertEqual(report["linked_sources"], [])
        self.assertNotIn("escaped payload marker", rendered)

    def test_reconstruction_opens_read_only_and_leaves_fixture_tree_unchanged(self) -> None:
        path = self._claude_session(
            self.CLAUDE_ONE,
            [self._claude_message("zero write marker")],
        )
        before = self._tree_state()
        real_os_open = os.open

        with mock.patch.object(sessions_module.os, "open", wraps=real_os_open) as opened:
            report = self._reconstruct(path)

        write_mask = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
        self.assertTrue(opened.called)
        for call in opened.call_args_list:
            self.assertGreaterEqual(len(call.args), 2)
            self.assertEqual(call.args[1] & write_mask, 0)
        self.assertEqual(self._tree_state(), before)
        self.assertEqual([event["content"] for event in report["events"]], ["zero write marker"])


if __name__ == "__main__":
    unittest.main()
