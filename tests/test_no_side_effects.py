from __future__ import annotations

# ruff: noqa: E402

import builtins
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
sys.dont_write_bytecode = True

from session_continuity import cli, commands
from session_continuity.contracts import InvalidInputError
from session_continuity.handoff import normalize_payload, publish_handoff, render_document
from session_continuity.project_facts import GitFacts, GitStatusCounts
from session_continuity.sessions import RecoveryLimits, reconstruct


_WRITE_OPEN_FLAGS = 0
for _flag_name in ("O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC", "O_EXCL"):
    _WRITE_OPEN_FLAGS |= int(getattr(os, _flag_name, 0))


def _snapshot_tree(root: Path) -> dict[str, tuple[object, ...]]:
    snapshot: dict[str, tuple[object, ...]] = {}
    paths = [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]
    for path in paths:
        relative = "." if path == root else path.relative_to(root).as_posix()
        info = path.stat(follow_symlinks=False)
        if path.is_symlink():
            snapshot[relative] = ("symlink", os.readlink(path), info.st_mtime_ns)
        elif path.is_file():
            snapshot[relative] = (
                "file",
                path.read_bytes(),
                info.st_size,
                info.st_mtime_ns,
            )
        elif path.is_dir():
            snapshot[relative] = ("directory", info.st_mtime_ns)
        else:
            snapshot[relative] = ("other", info.st_mode, info.st_mtime_ns)
    return snapshot


def _assert_no_derived_storage(test: unittest.TestCase, root: Path) -> None:
    forbidden_names = {
        "__pycache__",
        ".cache",
        "cache",
        ".index",
        "index",
        ".digest",
        "digest",
    }
    forbidden_suffixes = {
        ".pyc",
        ".pyo",
        ".cache",
        ".idx",
        ".index",
        ".digest",
        ".sha256",
        ".db",
        ".sqlite",
        ".sqlite3",
    }
    offenders: list[str] = []
    for path in root.rglob("*"):
        lowered_parts = {part.casefold() for part in path.relative_to(root).parts}
        if lowered_parts & forbidden_names or path.suffix.casefold() in forbidden_suffixes:
            offenders.append(path.relative_to(root).as_posix())
    test.assertEqual([], offenders)


@contextmanager
def _reject_filesystem_mutations():
    original_builtin_open = builtins.open
    original_io_open = io.open
    original_os_open = os.open

    def mode_is_writable(mode: object) -> bool:
        return isinstance(mode, str) and any(marker in mode for marker in ("w", "a", "x", "+"))

    def guarded_builtin_open(file, mode="r", *args, **kwargs):
        if mode_is_writable(mode):
            raise AssertionError(f"write-capable builtins.open attempted for {file!s}")
        return original_builtin_open(file, mode, *args, **kwargs)

    def guarded_io_open(file, mode="r", *args, **kwargs):
        if mode_is_writable(mode):
            raise AssertionError(f"write-capable io.open attempted for {file!s}")
        return original_io_open(file, mode, *args, **kwargs)

    def guarded_os_open(path, flags, *args, **kwargs):
        if int(flags) & _WRITE_OPEN_FLAGS:
            raise AssertionError(f"write-capable os.open attempted for {path!s}")
        return original_os_open(path, flags, *args, **kwargs)

    def reject_mutation(*args, **kwargs):
        target = args[0] if args else "filesystem"
        raise AssertionError(f"filesystem mutation attempted for {target!s}")

    with (
        patch("builtins.open", new=guarded_builtin_open),
        patch("io.open", new=guarded_io_open),
        patch("os.open", new=guarded_os_open),
        patch("os.mkdir", new=reject_mutation),
        patch("os.makedirs", new=reject_mutation),
        patch("os.remove", new=reject_mutation),
        patch("os.unlink", new=reject_mutation),
        patch("os.rename", new=reject_mutation),
        patch("os.replace", new=reject_mutation),
        patch("os.rmdir", new=reject_mutation),
        patch("os.removedirs", new=reject_mutation),
    ):
        yield


class NoSideEffectsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.base = Path(self._temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()
        self.empty_project = self.base / "empty-project"
        self.empty_project.mkdir()
        self.claude_root = self.base / "claude-fixtures"
        self.codex_root = self.base / "codex-fixtures"
        self.home = self.base / "synthetic-home"
        self.claude_root.mkdir()
        self.codex_root.mkdir()
        self.home.mkdir()

        self.git_status = GitStatusCounts()
        self.git_facts = GitFacts(
            root=self.project,
            is_repository=False,
            head=None,
            branch=None,
            detached=False,
            status=self.git_status,
        )
        self.git_metadata = {
            "is_repository": False,
            "head": None,
            "branch": None,
            "detached": False,
            "status": {
                "entries": 0,
                "staged": 0,
                "unstaged": 0,
                "untracked": 0,
                "conflicted": 0,
                "dirty": False,
            },
        }
        self.handoff_path = self._write_synthetic_handoff()
        self.session_path = self.project / "synthetic-session.jsonl"
        self.session_path.write_text(
            json.dumps(
                {
                    "role": "user",
                    "content": "SYNTHETIC_ACTION create marker.txt",
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def _write_synthetic_handoff(self) -> Path:
        payload = normalize_payload(
            {
                "goal": "Verify report-only synthetic fixture behavior",
                "verified_state": ["Synthetic fixture is ready"],
                "evidence_provenance": ["E-001: Synthetic fixture evidence"],
                "exact_stopping_point": "No action has run",
                "next_actions": [
                    {
                        "order": 1,
                        "status": "pending",
                        "action": "SYNTHETIC_ACTION create marker.txt",
                        "targets": ["marker.txt"],
                        "depends_on": [],
                        "acceptance": "The inert action remains report data",
                        "evidence_refs": ["E-001"],
                    }
                ],
            }
        )
        metadata = {
            "schema_version": 1,
            "created_at_local": "2026-01-02T03:04:05+00:00",
            "created_at_utc": "2026-01-02T03:04:05Z",
            "timezone_offset": "+0000",
            "focus": "synthetic fixture",
            "project_root": ".",
            "root_mode": "cwd",
            "git": self.git_metadata,
            "artifact_anchors": [],
        }
        document, _, _ = render_document(payload, metadata)
        handoff_root = self.project / ".handoffs"
        handoff_root.mkdir()
        path = handoff_root / "synthetic.md"
        path.write_bytes(document)
        return path

    def assert_tree_unchanged(self, before: dict[str, tuple[object, ...]]) -> None:
        self.assertEqual(before, _snapshot_tree(self.base))
        _assert_no_derived_storage(self, self.base)

    def test_resume_is_read_only_and_does_not_execute_next_actions(self) -> None:
        before = _snapshot_tree(self.base)

        with (
            patch.object(commands, "resolve_project_root", return_value=self.project),
            patch.object(commands, "collect_git_facts", return_value=self.git_facts),
            _reject_filesystem_mutations(),
        ):
            result, allowed_literals = commands.resume(
                invocation_cwd=self.project,
                handoff_path=self.handoff_path,
            )

        self.assertTrue(result["ok"])
        self.assertEqual("resume", result["action"])
        self.assertEqual("RESTORED", result["report"]["status"])
        self.assertEqual("SYNTHETIC_ACTION create marker.txt", result["report"]["next_actions"][0]["action"])
        self.assertEqual((), allowed_literals)
        self.assertFalse((self.project / "marker.txt").exists())
        self.assert_tree_unchanged(before)

    def test_synthetic_session_reconstruction_is_read_only_and_inert(self) -> None:
        before = _snapshot_tree(self.base)
        limits = RecoveryLimits(
            max_sessions=3,
            max_candidates=8,
            max_discovery_entries=64,
            max_session_bytes=64 * 1024,
            max_total_session_bytes=128 * 1024,
            max_topic_scan_bytes=16 * 1024,
            max_line_bytes=8 * 1024,
            max_events=16,
            max_event_chars=2 * 1024,
            max_output_chars=8 * 1024,
            max_evidence_gaps=16,
            max_link_files=2,
            max_link_bytes=8 * 1024,
            max_path_chars=2 * 1024,
            max_structured_items=16,
            max_structured_depth=4,
            topic_threshold=0.70,
        )

        with _reject_filesystem_mutations():
            report = reconstruct(
                f"path:{self.session_path}",
                self.project,
                limits=limits,
                home=self.home,
                claude_root=self.claude_root,
                codex_root=self.codex_root,
                follow_structured_links=False,
            )

        self.assertEqual("report_only", report["mode"])
        self.assertEqual(1, report["stats"]["sessions"])
        self.assertEqual(1, report["stats"]["events"])
        self.assertEqual(
            "SYNTHETIC_ACTION create marker.txt", report["events"][0]["content"]
        )
        self.assertFalse((self.project / "marker.txt").exists())
        self.assert_tree_unchanged(before)

    def test_deep_command_uses_bounded_default_without_writes(self) -> None:
        before = _snapshot_tree(self.base)
        observed: dict[str, object] = {}

        def synthetic_reconstruct(selector, root, *, limits):
            observed["selector"] = selector
            observed["root"] = root
            observed["max_sessions"] = limits.max_sessions
            return {
                "schema_version": 1,
                "mode": "report_only",
                "selector": {"kind": "topic", "value": selector},
                "sessions": [],
                "events": [],
                "evidence_gaps": [],
                "linked_sources": [],
                "truncated": False,
                "stats": {
                    "sessions": 0,
                    "events": 0,
                    "evidence_gaps": 0,
                    "linked_sources": 0,
                    "visible_characters": 0,
                },
            }

        with (
            patch.object(commands, "resolve_project_root", return_value=self.project),
            patch.object(commands, "reconstruct", side_effect=synthetic_reconstruct),
            _reject_filesystem_mutations(),
        ):
            result, allowed_literals = commands.deep(
                invocation_cwd=self.project,
                selector="synthetic-topic",
            )

        self.assertTrue(result["ok"])
        self.assertEqual("deep", result["action"])
        self.assertEqual(RecoveryLimits().max_sessions, observed["max_sessions"])
        self.assertEqual((), allowed_literals)
        self.assert_tree_unchanged(before)

    def test_cli_parameter_errors_do_not_dispatch_or_touch_files(self) -> None:
        invalid_arguments = (
            [],
            ["unknown"],
            ["resume"],
            ["resume", "one.md", "extra"],
            ["deep"],
            ["deep", "topic", "extra"],
            ["create", "focus", "extra"],
        )

        for argv in invalid_arguments:
            with self.subTest(argv=argv):
                before = _snapshot_tree(self.base)
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    patch.object(cli.os, "getcwd", return_value=str(self.project)),
                    patch.object(cli, "create", side_effect=AssertionError("create dispatched")),
                    patch.object(cli, "resume", side_effect=AssertionError("resume dispatched")),
                    patch.object(cli, "deep", side_effect=AssertionError("deep dispatched")),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                    _reject_filesystem_mutations(),
                ):
                    exit_code = cli.main(argv)

                self.assertEqual(2, exit_code)
                payload = json.loads(stdout.getvalue())
                self.assertFalse(payload["ok"])
                self.assertEqual("invalid_argument", payload["error"]["code"])
                self.assert_tree_unchanged(before)

    def test_malformed_create_request_has_zero_side_effects(self) -> None:
        before = _snapshot_tree(self.base)
        stdout = io.StringIO()

        with (
            patch.object(cli.os, "getcwd", return_value=str(self.empty_project)),
            patch.object(cli.sys, "stdin", io.StringIO("{")),
            patch.object(cli, "create", side_effect=AssertionError("create dispatched")),
            redirect_stdout(stdout),
            _reject_filesystem_mutations(),
        ):
            exit_code = cli.main(["create"])

        self.assertEqual(2, exit_code)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual("invalid_argument", payload["error"]["code"])
        self.assertFalse((self.empty_project / ".handoffs").exists())
        self.assert_tree_unchanged(before)

    def test_invalid_publish_payload_is_rejected_before_any_write(self) -> None:
        before = _snapshot_tree(self.base)

        with _reject_filesystem_mutations():
            with self.assertRaises(InvalidInputError):
                publish_handoff(
                    self.empty_project,
                    {"goal": ""},
                    focus="synthetic fixture",
                    root_mode="cwd",
                    git=self.git_metadata,
                )

        self.assertFalse((self.empty_project / ".handoffs").exists())
        self.assert_tree_unchanged(before)


if __name__ == "__main__":
    unittest.main()
