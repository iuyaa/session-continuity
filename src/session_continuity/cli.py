"""Command-line adapter for Session Continuity."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Any, NoReturn

from . import __version__
from .commands import create, deep, resume
from .contracts import DEFAULT_LIMITS, DomainError, ExitCode, InvalidInputError
from .redaction import redact_output


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise InvalidInputError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="session-continuity",
        description="Create or restore project context across local sessions.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="Create one project handoff")
    create_parser.add_argument("focus", nargs="?", default="")

    resume_parser = subparsers.add_parser("resume", help="Restore one named handoff")
    resume_parser.add_argument("handoff_path")

    deep_parser = subparsers.add_parser("deep", help="Restore session evidence")
    deep_parser.add_argument("selector")
    return parser


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise InvalidInputError("request JSON contains a duplicate key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise InvalidInputError("request JSON contains a non-finite number")


def _read_create_request() -> tuple[dict[str, Any], dict[str, str]]:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(DEFAULT_LIMITS.max_request_bytes + 1)
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    else:
        raw_bytes = bytes(raw)
    if len(raw_bytes) > DEFAULT_LIMITS.max_request_bytes:
        raise InvalidInputError("create request exceeds the byte limit")
    if raw_bytes.startswith(b"\xef\xbb\xbf") or b"\x00" in raw_bytes:
        raise InvalidInputError("create request encoding is invalid")
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise InvalidInputError("create request is not strict UTF-8") from error
    try:
        request = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except InvalidInputError:
        raise
    except json.JSONDecodeError as error:
        raise InvalidInputError("create request JSON is malformed") from error
    if not isinstance(request, dict):
        raise InvalidInputError("create request must be an object")
    unknown = set(request) - {"handoff", "named_artifacts"}
    if unknown:
        raise InvalidInputError("create request contains an unknown field")
    handoff = request.get("handoff")
    artifacts = request.get("named_artifacts", {})
    if not isinstance(handoff, dict):
        raise InvalidInputError("create request needs a handoff object")
    if not isinstance(artifacts, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in artifacts.items()
    ):
        raise InvalidInputError("named_artifacts must map names to paths")
    return handoff, artifacts


def _emit(payload: dict[str, Any], *, allowed_literals: Sequence[str] = ()) -> None:
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    encoded_literals = tuple(
        json.dumps(literal, ensure_ascii=False)[1:-1]
        for literal in allowed_literals
        if literal
    )
    safe = redact_output(
        rendered,
        allowed_literals=(*allowed_literals, *encoded_literals),
    ).value
    sys.stdout.write(safe + "\n")


def _error_payload(error: DomainError) -> dict[str, Any]:
    return {"ok": False, "error": error.as_dict()}


def main(argv: Sequence[str] | None = None) -> int:
    if sys.version_info < (3, 11):
        sys.stderr.write("session-continuity requires Python 3.11+\n")
        return int(ExitCode.USAGE)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        cwd = os.getcwd()
        if args.command == "create":
            handoff, artifacts = _read_create_request()
            result, allowed = create(
                invocation_cwd=cwd,
                focus=args.focus,
                handoff=handoff,
                named_artifacts=artifacts,
            )
        elif args.command == "resume":
            result, allowed = resume(
                invocation_cwd=cwd,
                handoff_path=args.handoff_path,
            )
        else:
            result, allowed = deep(invocation_cwd=cwd, selector=args.selector)
        _emit(result, allowed_literals=allowed)
        return int(ExitCode.SUCCESS)
    except DomainError as error:
        _emit(_error_payload(error))
        return int(error.exit_code)
    except (OSError, UnicodeError, ValueError, TypeError):
        payload = {
            "ok": False,
            "error": {
                "code": "internal_error",
                "exit_code": int(ExitCode.IO_ERROR),
                "message": "command failed",
            },
        }
        _emit(payload)
        return int(ExitCode.IO_ERROR)


if __name__ == "__main__":
    raise SystemExit(main())
