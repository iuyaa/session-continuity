from __future__ import annotations

import copy
import hashlib
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from session_continuity import handoff  # noqa: E402
from session_continuity.contracts import InvalidInputError  # noqa: E402


def synthetic_payload() -> dict[str, object]:
    return {
        "goal": "Synthetic continuity goal.",
        "verified_state": ["Synthetic verification is recorded."],
        "reported_state": ["Synthetic report is recorded."],
        "in_progress": ["Synthetic work is paused."],
        "deferred_parked": [],
        "not_done": ["Synthetic follow-up remains."],
        "decisions_constraints": ["Use fixture data only."],
        "files_changed": ["src/fixture.py"],
        "commands_run": ["python -m unittest"],
        "verification": ["Synthetic check passed."],
        "artifacts": [],
        "environment": ["Python 3.11"],
        "evidence_provenance": [
            "E-001: Synthetic source observation.",
            "E-002: Synthetic verification observation.",
        ],
        "exact_stopping_point": "Stopped after synthetic verification.",
        "next_actions": [
            {
                "order": 1,
                "status": "ready",
                "action": "Inspect the first synthetic fixture.",
                "targets": ["src/fixture.py"],
                "depends_on": [],
                "acceptance": "The first fixture is inspected.",
                "evidence_refs": ["E-001"],
            },
            {
                "order": 2,
                "status": "blocked",
                "action": "Verify the second synthetic fixture.",
                "targets": ["tests/test_fixture.py"],
                "depends_on": ["1"],
                "acceptance": "The second fixture is verified.",
                "evidence_refs": ["E-002"],
            },
        ],
        "suggested_skills": ["synthetic-skill"],
    }


def synthetic_metadata() -> dict[str, object]:
    return {
        "schema_version": 1,
        "created_at_local": "2026-02-03T04:05:06+05:30",
        "created_at_utc": "2026-02-02T22:35:06Z",
        "timezone_offset": "+0530",
        "focus": "fixture focus",
        "project_root": ".",
        "root_mode": "cwd",
        "git": {"is_repository": False},
        "artifact_anchors": [],
    }


class HandoffDocumentTests(unittest.TestCase):
    def test_document_has_exactly_the_fixed_nineteen_headings(self) -> None:
        document, _, _ = handoff.render_document(
            handoff.normalize_payload(synthetic_payload()), synthetic_metadata()
        )
        trailer = handoff.TRAILER_RE.search(document)
        self.assertIsNotNone(trailer)
        assert trailer is not None
        body = document[: trailer.start()].decode("utf-8")

        headings = tuple(re.findall(r"(?m)^#{1,6} .+$", body))
        self.assertEqual(len(headings), 19)
        self.assertEqual(headings, handoff.HEADINGS)
        parsed = handoff.parse_document(document)
        self.assertEqual(parsed.sections["Goal"], "Synthetic continuity goal.")

    def test_multiple_next_actions_remain_ordered_and_structured(self) -> None:
        normalized = handoff.normalize_payload(synthetic_payload())

        self.assertEqual([item["order"] for item in normalized["next_actions"]], [1, 2])
        self.assertEqual(
            [item["action"] for item in normalized["next_actions"]],
            [
                "Inspect the first synthetic fixture.",
                "Verify the second synthetic fixture.",
            ],
        )
        document, _, _ = handoff.render_document(normalized, synthetic_metadata())
        parsed = handoff.parse_document(document)
        self.assertEqual([item["order"] for item in parsed.next_actions], [1, 2])
        self.assertEqual(parsed.next_actions[1]["depends_on"], ["1"])

    def test_next_action_validation_rejects_order_reference_and_target_errors(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []

        noncontiguous = copy.deepcopy(synthetic_payload())
        noncontiguous["next_actions"][1]["order"] = 3  # type: ignore[index]
        cases.append(("noncontiguous", noncontiguous))

        malformed_reference = copy.deepcopy(synthetic_payload())
        malformed_reference["next_actions"][0]["evidence_refs"] = ["evidence-one"]  # type: ignore[index]
        cases.append(("malformed-reference", malformed_reference))

        undefined_reference = copy.deepcopy(synthetic_payload())
        undefined_reference["next_actions"][0]["evidence_refs"] = ["E-999"]  # type: ignore[index]
        cases.append(("undefined-reference", undefined_reference))

        traversing_target = copy.deepcopy(synthetic_payload())
        traversing_target["next_actions"][0]["targets"] = ["../outside.py"]  # type: ignore[index]
        cases.append(("traversing-target", traversing_target))

        unknown_field = copy.deepcopy(synthetic_payload())
        unknown_field["next_actions"][0]["unexpected"] = True  # type: ignore[index]
        cases.append(("unknown-field", unknown_field))

        for name, payload in cases:
            with self.subTest(name=name):
                with self.assertRaises(InvalidInputError):
                    handoff.normalize_payload(payload)

    def test_completion_trailer_hashes_the_exact_document_body(self) -> None:
        document, digest, _ = handoff.render_document(
            handoff.normalize_payload(synthetic_payload()), synthetic_metadata()
        )
        trailer = handoff.TRAILER_RE.search(document)
        self.assertIsNotNone(trailer)
        assert trailer is not None
        body = document[: trailer.start()]

        self.assertEqual(digest, hashlib.sha256(body).hexdigest())
        self.assertEqual(trailer.group(1).decode("ascii"), digest)
        self.assertTrue(document.endswith(b" -->\n"))

        tampered = document.replace(b"Synthetic continuity goal.", b"Synthetic continuity goam.", 1)
        with self.assertRaisesRegex(InvalidInputError, "hash does not match"):
            handoff.parse_document(tampered)
        with self.assertRaisesRegex(InvalidInputError, "completion trailer"):
            handoff.parse_document(body)

    def test_system_local_instant_has_offset_and_equivalent_utc_value(self) -> None:
        local, utc, offset = handoff._local_instant()

        self.assertIsNotNone(local.utcoffset())
        self.assertEqual(local.astimezone(timezone.utc), utc)
        self.assertIs(utc.tzinfo, timezone.utc)
        self.assertEqual(offset, local.strftime("%z") or "+0000")
        self.assertRegex(offset, r"^[+-]\d{4}$")

    def test_filename_uses_local_timestamp_and_offset_while_metadata_records_utc(self) -> None:
        local_zone = timezone(timedelta(hours=5, minutes=30))
        local = datetime(2026, 2, 3, 4, 5, 6, tzinfo=local_zone)
        utc = local.astimezone(timezone.utc)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(
                    handoff, "_local_instant", return_value=(local, utc, "+0530")
                ),
                mock.patch.object(handoff.secrets, "token_hex", return_value="01020304"),
            ):
                publication = handoff.publish_handoff(
                    root,
                    synthetic_payload(),
                    focus="Fixture Focus",
                    root_mode="cwd",
                    git={"is_repository": False},
                )

            self.assertEqual(
                publication.path.name,
                "20260203T040506+0530-fixture-focus-01020304.md",
            )
            self.assertEqual(publication.created_local, "2026-02-03T04:05:06+05:30")
            self.assertEqual(publication.created_utc, "2026-02-02T22:35:06Z")
            self.assertEqual(publication.timezone_offset, "+0530")
            parsed = handoff.parse_document(publication.path.read_bytes())
            self.assertEqual(
                parsed.metadata["created_at_local"], publication.created_local
            )
            self.assertEqual(parsed.metadata["created_at_utc"], publication.created_utc)


if __name__ == "__main__":
    unittest.main()
