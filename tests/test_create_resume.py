from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
WRAPPER = ROOT / "scripts" / "session_continuity.py"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from session_continuity import commands, handoff  # noqa: E402
from session_continuity.contracts import (  # noqa: E402
    DomainCode,
    FilesystemError,
    GitError,
)
from session_continuity.project_facts import (  # noqa: E402
    GitFacts,
    GitStatusCounts,
    collect_git_facts,
)


def synthetic_payload() -> dict[str, object]:
    return {
        "goal": "Synthetic create and resume goal.",
        "verified_state": ["Synthetic state is verified."],
        "reported_state": [],
        "in_progress": [],
        "deferred_parked": [],
        "not_done": ["No action has been executed."],
        "decisions_constraints": ["Recovery remains report-only."],
        "files_changed": [],
        "commands_run": [],
        "verification": ["Synthetic verification only."],
        "artifacts": [],
        "environment": ["Temporary fixture environment."],
        "evidence_provenance": ["E-001: Synthetic fixture evidence."],
        "exact_stopping_point": "Stopped before the inert action.",
        "next_actions": [
            {
                "order": 1,
                "status": "ready",
                "action": "Create an execution marker.",
                "targets": ["executed.flag"],
                "depends_on": [],
                "acceptance": "The marker would exist only after explicit execution.",
                "evidence_refs": ["E-001"],
            }
        ],
        "suggested_skills": [],
    }


def action_payload() -> dict[str, object]:
    payload = synthetic_payload()
    statuses = (
        "done",
        "parked",
        "blocked",
        "pending",
        "ready",
        "in_progress",
        "pending",
    )
    payload["next_actions"] = [
        {
            "order": order,
            "status": status,
            "action": f"Conditional synthetic action {order}.",
            "targets": [f"synthetic-target-{order}"],
            "depends_on": [],
            "acceptance": f"Synthetic acceptance {order}.",
            "evidence_refs": ["E-001"],
        }
        for order, status in enumerate(statuses, 1)
    ]
    payload["artifacts"] = ["release-notes.json", "app/DESIGN.md"]
    payload["suggested_skills"] = [
        "run — verify runtime behavior",
        "review-changes — review the next delta",
    ]
    return payload


def git_facts(root: Path, *, branch: str | None = None) -> GitFacts:
    return GitFacts(
        root=root,
        is_repository=branch is not None,
        head="a" * 40 if branch is not None else None,
        branch=branch,
        detached=False,
        status=GitStatusCounts(),
    )


def git_metadata(facts: GitFacts) -> dict[str, object]:
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


def snapshot_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


class GitFactTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "Git executable is unavailable")
    def test_product_handoff_directory_is_excluded_from_status_drift(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(
                ["git", "init", "-q"],
                cwd=root,
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (root / ".handoffs").mkdir()
            (root / ".handoffs" / "fixture.md").write_text(
                "synthetic handoff", encoding="utf-8"
            )
            (root / "visible.txt").write_text("visible drift", encoding="utf-8")

            facts = collect_git_facts(root)

            self.assertEqual(1, facts.status.entries)
            self.assertEqual(1, facts.status.untracked)


class ExclusivePublicationTests(unittest.TestCase):
    def test_exclusive_write_uses_o_excl_and_preserves_existing_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            new_path = root / "new.md"
            original_open = os.open
            with mock.patch.object(handoff.os, "open", wraps=original_open) as open_mock:
                handoff._exclusive_write(new_path, b"new synthetic bytes")

            flags = open_mock.call_args.args[1]
            self.assertTrue(flags & os.O_EXCL)
            self.assertEqual(new_path.read_bytes(), b"new synthetic bytes")

            existing_path = root / "existing.md"
            existing_path.write_bytes(b"original synthetic bytes")
            with self.assertRaises(FileExistsError):
                handoff._exclusive_write(existing_path, b"replacement bytes")
            self.assertEqual(existing_path.read_bytes(), b"original synthetic bytes")

    def test_collision_retries_new_name_reads_back_and_leaves_collision_unchanged(self) -> None:
        zone = timezone(timedelta(hours=-4))
        local = datetime(2026, 7, 8, 9, 10, 11, tzinfo=zone)
        utc = local.astimezone(timezone.utc)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            handoff_dir = root / ".handoffs"
            handoff_dir.mkdir()
            collision = handoff_dir / "20260708T091011-0400-fixture-deadbeef.md"
            collision.write_bytes(b"pre-existing synthetic bytes")

            original_readonly = handoff.open_verified_readonly
            with (
                mock.patch.object(
                    handoff, "_local_instant", return_value=(local, utc, "-0400")
                ),
                mock.patch.object(
                    handoff.secrets,
                    "token_hex",
                    side_effect=["deadbeef", "cafebabe"],
                ),
                mock.patch.object(
                    handoff,
                    "open_verified_readonly",
                    wraps=original_readonly,
                ) as readback,
            ):
                publication = handoff.publish_handoff(
                    root,
                    synthetic_payload(),
                    focus="fixture",
                    root_mode="cwd",
                    git={"is_repository": False},
                )

            self.assertEqual(collision.read_bytes(), b"pre-existing synthetic bytes")
            self.assertEqual(
                publication.path.name,
                "20260708T091011-0400-fixture-cafebabe.md",
            )
            self.assertGreaterEqual(readback.call_count, 1)
            self.assertEqual(publication.path.read_bytes(), handoff.parse_document(publication.path.read_bytes()).raw)

    def test_readback_mismatch_removes_only_the_new_candidate(self) -> None:
        local = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        candidate_name = "20260102T030405+0000-fixture-01010101.md"

        with TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(
                    handoff, "_local_instant", return_value=(local, local, "+0000")
                ),
                mock.patch.object(handoff.secrets, "token_hex", return_value="01010101"),
                mock.patch.object(
                    handoff,
                    "open_verified_readonly",
                    return_value=io.BytesIO(b"mismatched readback"),
                ),
            ):
                with self.assertRaisesRegex(FilesystemError, "readback differs"):
                    handoff.publish_handoff(
                        root,
                        synthetic_payload(),
                        focus="fixture",
                        root_mode="cwd",
                        git={"is_repository": False},
                    )

            self.assertFalse((root / ".handoffs" / candidate_name).exists())


class ResumeTests(unittest.TestCase):
    def test_resume_is_report_only_and_reports_git_and_artifact_drift(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"synthetic version one")
            saved_git = git_facts(root, branch="fixture-main")
            anchor = {
                "name": "fixture-artifact",
                "path": "artifact.bin",
                "size": artifact.stat().st_size,
                "mtime_ns": artifact.stat().st_mtime_ns,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            publication = handoff.publish_handoff(
                root,
                synthetic_payload(),
                focus="resume fixture",
                root_mode="git",
                git=git_metadata(saved_git),
                artifact_anchors=[anchor],
            )

            artifact.write_bytes(b"synthetic version two")
            before_resume = snapshot_files(root)
            current_git = git_facts(root, branch="fixture-other")
            with (
                mock.patch.object(commands, "resolve_project_root", return_value=root),
                mock.patch.object(commands, "collect_git_facts", return_value=current_git),
            ):
                result, allowed_literals = commands.resume(
                    invocation_cwd=root,
                    handoff_path=publication.path,
                )

            self.assertTrue(result["ok"])
            self.assertEqual(result["action"], "resume")
            report = result["report"]
            self.assertEqual(report["mode"], "report_only")
            self.assertEqual(report["status"], "DRIFTED")
            self.assertEqual(allowed_literals, ())
            drift_kinds = {item["kind"] for item in report["drift"]}
            self.assertIn("git_branch_changed", drift_kinds)
            self.assertIn("artifact_changed", drift_kinds)
            self.assertEqual(report["continuation"]["guidance"], "review_drift")
            self.assertFalse(report["continuation"]["execution_authorized"])
            self.assertEqual(
                report["drift_scope"]["named_artifacts"],
                {
                    "coverage": "explicit_saved_anchors_only",
                    "saved": 1,
                    "checked": 1,
                    "matched": 0,
                    "changed": 1,
                    "unavailable": 0,
                    "metadata_valid": True,
                },
            )
            self.assertEqual(report["next_actions"][0]["action"], "Create an execution marker.")
            self.assertFalse((root / "executed.flag").exists())
            self.assertEqual(snapshot_files(root), before_resume)

    def test_resume_without_drift_reports_restored_and_preserves_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            current_git = git_facts(root)
            publication = handoff.publish_handoff(
                root,
                synthetic_payload(),
                focus="restored fixture",
                root_mode="cwd",
                git=git_metadata(current_git),
            )
            before_resume = snapshot_files(root)

            with (
                mock.patch.object(commands, "resolve_project_root", return_value=root),
                mock.patch.object(commands, "collect_git_facts", return_value=current_git),
            ):
                result, _ = commands.resume(
                    invocation_cwd=root,
                    handoff_path=publication.path,
                )

            self.assertEqual(result["report"]["status"], "RESTORED")
            self.assertEqual(result["report"]["drift"], [])
            self.assertEqual(
                result["report"]["current_project"]["git_probe"],
                "checked_non_repository",
            )
            self.assertEqual(
                result["report"]["continuation"]["guidance"],
                "verify_scope",
            )
            self.assertEqual(snapshot_files(root), before_resume)
            self.assertFalse((root / "executed.flag").exists())

    def test_legacy_v1_missing_git_fields_are_limited_not_drifted(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            current_git = git_facts(root)
            publication = handoff.publish_handoff(
                root,
                synthetic_payload(),
                focus="legacy git fixture",
                root_mode="cwd",
                git={"is_repository": False},
            )
            before_resume = snapshot_files(root)

            with (
                mock.patch.object(commands, "resolve_project_root", return_value=root),
                mock.patch.object(commands, "collect_git_facts", return_value=current_git),
            ):
                result, _ = commands.resume(
                    invocation_cwd=root,
                    handoff_path=publication.path,
                )

            report = result["report"]
            self.assertEqual(report["status"], "RESTORED")
            self.assertEqual(report["drift"], [])
            self.assertEqual(
                report["drift_scope"]["git"]["comparison"],
                "limited_by_saved_v1_fields",
            )
            self.assertEqual(
                report["drift_scope"]["git"]["missing_saved_fields"],
                ["head", "branch", "detached", "status"],
            )
            self.assertEqual(report["continuation"]["guidance"], "verify_scope")
            self.assertEqual(snapshot_files(root), before_resume)

    def test_resume_derives_concise_continuation_without_losing_full_actions(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            current_git = git_facts(root)
            publication = handoff.publish_handoff(
                root,
                action_payload(),
                focus="continuation fixture",
                root_mode="cwd",
                git=git_metadata(current_git),
            )
            before_resume = snapshot_files(root)

            with (
                mock.patch.object(commands, "resolve_project_root", return_value=root),
                mock.patch.object(commands, "collect_git_facts", return_value=current_git),
            ):
                result, _ = commands.resume(
                    invocation_cwd=root,
                    handoff_path=publication.path,
                )

            report = result["report"]
            continuation = report["continuation"]
            self.assertEqual(len(report["next_actions"]), 7)
            self.assertEqual(
                [item["order"] for item in continuation["next_actions"]["items"]],
                [2, 3, 4, 5, 6],
            )
            self.assertEqual(continuation["next_actions"]["omitted"], 1)
            self.assertEqual(
                [item["status"] for item in continuation["next_actions"]["items"]],
                ["parked", "blocked", "pending", "ready", "in_progress"],
            )
            self.assertEqual(
                continuation["canonical_references"]["textual"],
                ["release-notes.json", "app/DESIGN.md"],
            )
            self.assertEqual(continuation["stop"], "await_explicit_user_instruction")
            self.assertFalse(continuation["execution_authorized"])
            self.assertEqual(report["sha256"], report["body_sha256"])
            self.assertEqual(report["file_sha256"], publication.file_sha256)
            self.assertEqual(snapshot_files(root), before_resume)

    def test_resume_reports_unavailable_git_without_fabricated_drift(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            saved_git = git_facts(root, branch="fixture-main")
            publication = handoff.publish_handoff(
                root,
                synthetic_payload(),
                focus="git unavailable fixture",
                root_mode="git",
                git=git_metadata(saved_git),
            )
            before_resume = snapshot_files(root)
            unavailable = GitError(
                "Git executable is unavailable",
                code=DomainCode.GIT_UNAVAILABLE,
            )

            with (
                mock.patch.object(commands, "resolve_project_root", return_value=root),
                mock.patch.object(
                    commands,
                    "collect_git_facts",
                    side_effect=unavailable,
                ),
            ):
                result, _ = commands.resume(
                    invocation_cwd=root,
                    handoff_path=publication.path,
                )

            report = result["report"]
            self.assertEqual(report["status"], "RESTORED")
            self.assertEqual(report["drift"], [])
            self.assertEqual(report["current_project"]["git_probe"], "unavailable")
            self.assertFalse(report["drift_scope"]["git"]["checked"])
            self.assertEqual(
                report["drift_scope"]["git"]["comparison"],
                "not_checked_current_unavailable",
            )
            self.assertEqual(report["continuation"]["guidance"], "verify_scope")
            self.assertEqual(snapshot_files(root), before_resume)
            self.assertFalse((root / "executed.flag").exists())


class WrapperIntegrationTests(unittest.TestCase):
    def test_wrapper_runs_from_unrelated_cwd_with_strict_stdin_request(self) -> None:
        request = {"handoff": synthetic_payload(), "named_artifacts": {}}

        with TemporaryDirectory() as directory:
            unrelated_cwd = Path(directory)
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONUTF8": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                }
            )
            completed = subprocess.run(
                [sys.executable, "-B", str(WRAPPER), "create", "wrapper fixture"],
                cwd=unrelated_cwd,
                input=json.dumps(request, ensure_ascii=False),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=30,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            response = json.loads(completed.stdout)
            self.assertTrue(response["ok"])
            self.assertEqual(response["action"], "create")
            created = Path(response["path"])
            self.assertEqual(response["sha256"], response["body_sha256"])
            self.assertEqual(
                response["file_sha256"],
                hashlib.sha256(created.read_bytes()).hexdigest(),
            )
            self.assertEqual(created.parent, unrelated_cwd / ".handoffs")
            self.assertTrue(created.is_file())
            self.assertEqual(len(list((unrelated_cwd / ".handoffs").glob("*.md"))), 1)
            self.assertEqual(list(unrelated_cwd.rglob("__pycache__")), [])
    def test_invalid_optional_artifacts_do_not_block_create(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            project = base / "project"
            project.mkdir()
            source = project / "src" / "module.py"
            source.parent.mkdir()
            source.write_text("value = 1\n", encoding="utf-8")
            sensitive = project / "reports" / "192.0.2.10" / "state.txt"
            sensitive.parent.mkdir(parents=True)
            sensitive.write_text("synthetic state\n", encoding="utf-8")
            outside = base / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            request = {
                "handoff": synthetic_payload(),
                "named_artifacts": {
                    "valid-relative": "src/module.py",
                    "valid-absolute": str(source),
                    "line-reference": "src/module.py:123",
                    "fragment-reference": "src/module.py#L123",
                    "missing": "src/missing.py",
                    "outside": str(outside),
                    "sensitive-path": "reports/192.0.2.10/state.txt",
                },
            }
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"

            completed = subprocess.run(
                [sys.executable, "-B", str(WRAPPER), "create", "artifact fixture"],
                cwd=project,
                input=json.dumps(request, ensure_ascii=False),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=30,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            response = json.loads(completed.stdout)
            self.assertTrue(response["ok"])
            self.assertEqual(
                response["named_artifacts"],
                {"requested": 7, "anchored": 2, "skipped": 5},
            )
            created = Path(response["path"])
            parsed = handoff.parse_document(created.read_bytes())
            self.assertEqual(
                {anchor["name"] for anchor in parsed.metadata["artifact_anchors"]},
                {"valid-relative", "valid-absolute"},
            )
            self.assertEqual(len(list((project / ".handoffs").glob("*.md"))), 1)
            self.assertEqual(list(project.rglob("__pycache__")), [])


if __name__ == "__main__":
    unittest.main()
