from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from session_continuity import cli  # noqa: E402
from session_continuity.contracts import (  # noqa: E402
    DEFAULT_LIMITS,
    ExitCode,
    InvalidInputError,
)


class _BinaryInput:
    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)


class ArgparseGrammarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = cli.build_parser()

    def test_accepts_exact_command_grammar(self) -> None:
        cases = (
            (["create"], {"command": "create", "focus": ""}),
            (["create", "focused handoff"], {"command": "create", "focus": "focused handoff"}),
            (
                ["resume", ".handoffs/fixture.md"],
                {"command": "resume", "handoff_path": ".handoffs/fixture.md"},
            ),
            (["deep", "synthetic topic"], {"command": "deep", "selector": "synthetic topic"}),
        )

        for argv, expected in cases:
            with self.subTest(argv=argv):
                self.assertEqual(vars(self.parser.parse_args(argv)), expected)

    def test_rejects_missing_unknown_and_extra_arguments(self) -> None:
        invalid_argv = (
            [],
            ["unknown"],
            ["create", "one", "two"],
            ["resume"],
            ["resume", "one.md", "two.md"],
            ["deep"],
            ["deep", "one", "two"],
        )

        for argv in invalid_argv:
            with self.subTest(argv=argv):
                with self.assertRaises(InvalidInputError):
                    self.parser.parse_args(argv)


class StrictStdinJsonTests(unittest.TestCase):
    def read_request(self, data: bytes):
        with mock.patch.object(cli.sys, "stdin", _BinaryInput(data)):
            return cli._read_create_request()

    def test_accepts_one_strict_utf8_json_object(self) -> None:
        request = {
            "handoff": {"goal": "synthetic goal"},
            "named_artifacts": {"fixture": "fixture.bin"},
        }

        handoff, artifacts = self.read_request(
            json.dumps(request, ensure_ascii=False).encode("utf-8")
        )

        self.assertEqual(handoff, {"goal": "synthetic goal"})
        self.assertEqual(artifacts, {"fixture": "fixture.bin"})

    def test_rejects_non_strict_or_noncanonical_request_json(self) -> None:
        invalid_requests = (
            b"",
            b"[]",
            b'{"handoff":{},"handoff":{}}',
            b'{"handoff":{},"value":NaN}',
            b'{"handoff":{},"unknown":true}',
            b'{"handoff":{},"named_artifacts":[]}',
            b'{"handoff":{},"named_artifacts":{"fixture":1}}',
            b'{"handoff":{}} trailing',
            b"\xef\xbb\xbf" + b'{"handoff":{}}',
            b'{"handoff":"\x00"}',
            b'{"handoff":"\xff"}',
        )

        for raw in invalid_requests:
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidInputError):
                    self.read_request(raw)

    def test_rejects_request_over_byte_limit_before_json_parsing(self) -> None:
        oversized = b"x" * (DEFAULT_LIMITS.max_request_bytes + 1)

        with self.assertRaisesRegex(InvalidInputError, "exceeds the byte limit"):
            self.read_request(oversized)

    def test_main_emits_one_json_error_for_duplicate_stdin_keys(self) -> None:
        stdout = io.StringIO()
        request = b'{"handoff":{},"handoff":{}}'

        with (
            mock.patch.object(cli.sys, "stdin", _BinaryInput(request)),
            mock.patch.object(cli.sys, "stdout", stdout),
        ):
            exit_code = cli.main(["create"])

        lines = stdout.getvalue().splitlines()
        self.assertEqual(exit_code, int(ExitCode.USAGE))
        self.assertEqual(len(lines), 1)
        self.assertEqual(
            json.loads(lines[0]),
            {
                "ok": False,
                "error": {
                    "code": "invalid_argument",
                    "exit_code": int(ExitCode.USAGE),
                    "message": "request JSON contains a duplicate key",
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
