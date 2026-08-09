"""Stable public contracts shared by session-continuity primitives.

The module deliberately keeps exception payloads small and machine-readable.  Exit
codes and domain codes are wire-level contracts: callers may branch on them and
should not need to parse human-readable exception messages.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Final, Mapping


class ExitCode(IntEnum):
    """Stable process exit codes exposed to command-line adapters."""

    SUCCESS = 0
    USAGE = 2
    VALIDATION_FAILED = 3
    INTEGRITY_FAILED = 4
    IO_ERROR = 5


class DomainCode(StrEnum):
    """Stable, transport-safe identifiers for expected domain failures."""

    INVALID_ARGUMENT = "invalid_argument"
    PATH_NOT_FOUND = "path_not_found"
    PATH_OUTSIDE_ROOT = "path_outside_root"
    UNSAFE_PATH = "unsafe_path"
    LIMIT_EXCEEDED = "limit_exceeded"
    REDACTION_INPUT = "redaction_input"
    REDACTION_RESIDUAL = "redaction_residual"
    GIT_UNAVAILABLE = "git_unavailable"
    GIT_COMMAND_FAILED = "git_command_failed"
    ARTIFACT_NOT_FOUND = "artifact_not_found"
    ARTIFACT_CHANGED = "artifact_changed"
    IO_ERROR = "io_error"


_EXIT_BY_DOMAIN: Final[Mapping[DomainCode, ExitCode]] = MappingProxyType(
    {
        DomainCode.INVALID_ARGUMENT: ExitCode.USAGE,
        DomainCode.PATH_NOT_FOUND: ExitCode.IO_ERROR,
        DomainCode.PATH_OUTSIDE_ROOT: ExitCode.INTEGRITY_FAILED,
        DomainCode.UNSAFE_PATH: ExitCode.INTEGRITY_FAILED,
        DomainCode.LIMIT_EXCEEDED: ExitCode.VALIDATION_FAILED,
        DomainCode.REDACTION_INPUT: ExitCode.VALIDATION_FAILED,
        DomainCode.REDACTION_RESIDUAL: ExitCode.VALIDATION_FAILED,
        DomainCode.GIT_UNAVAILABLE: ExitCode.VALIDATION_FAILED,
        DomainCode.GIT_COMMAND_FAILED: ExitCode.VALIDATION_FAILED,
        DomainCode.ARTIFACT_NOT_FOUND: ExitCode.IO_ERROR,
        DomainCode.ARTIFACT_CHANGED: ExitCode.INTEGRITY_FAILED,
        DomainCode.IO_ERROR: ExitCode.IO_ERROR,
    }
)


class DomainError(Exception):
    """Base class for an expected, stable session-continuity failure.

    ``context`` must contain only compact diagnostic facts.  It is intentionally
    excluded from ``str(error)`` so a log adapter cannot accidentally interpolate
    a path, token, or command output into a user-facing error.
    """

    default_code: DomainCode = DomainCode.INVALID_ARGUMENT

    def __init__(
        self,
        message: str,
        *,
        code: DomainCode | None = None,
        context: Mapping[str, str | int | float | bool | None] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.exit_code = _EXIT_BY_DOMAIN[self.code]
        self.context: Mapping[str, str | int | float | bool | None] = MappingProxyType(
            dict(context or {})
        )

    @property
    def domain_code(self) -> str:
        """Return the string form suitable for JSON and CLI diagnostics."""

        return self.code.value

    def as_dict(self) -> dict[str, object]:
        """Return a deterministic, serialization-friendly error payload."""

        payload: dict[str, object] = {
            "code": self.code.value,
            "exit_code": int(self.exit_code),
            "message": self.message,
        }
        if self.context:
            payload["context"] = dict(sorted(self.context.items()))
        return payload


class InvalidInputError(DomainError):
    """Raised when a caller supplies a malformed value."""

    default_code = DomainCode.INVALID_ARGUMENT


class PathSafetyError(DomainError):
    """Raised when a path is missing, escapes its root, or crosses a link."""

    default_code = DomainCode.UNSAFE_PATH


class LimitExceededError(DomainError):
    """Raised before or while a bounded operation exceeds its budget."""

    default_code = DomainCode.LIMIT_EXCEEDED


class RedactionError(DomainError):
    """Raised when redaction cannot produce verified output."""

    default_code = DomainCode.REDACTION_RESIDUAL


class GitError(DomainError):
    """Raised for unavailable, timed-out, malformed, or failed Git commands."""

    default_code = DomainCode.GIT_COMMAND_FAILED


class ArtifactError(DomainError):
    """Raised when an explicitly named artifact cannot be safely inspected."""

    default_code = DomainCode.ARTIFACT_NOT_FOUND


class FilesystemError(DomainError):
    """Raised for a stable filesystem I/O failure."""

    default_code = DomainCode.IO_ERROR


@dataclass(frozen=True, slots=True)
class Limits:
    """Resource ceilings for every operation that consumes untrusted input.

    Values are deliberately conservative for report generation.  A caller may
    pass a different immutable instance, but cannot disable a bound with zero or
    a negative value.
    """

    max_request_bytes: int = 256 * 1024
    max_handoff_bytes: int = 512 * 1024
    max_actions: int = 32
    max_list_items: int = 256
    max_text_chars: int = 64 * 1024
    git_timeout_seconds: float = 3.0
    max_git_output_bytes: int = 256 * 1024
    max_git_status_entries: int = 4_096
    max_artifacts: int = 128
    max_artifact_bytes: int = 64 * 1024 * 1024
    artifact_chunk_bytes: int = 128 * 1024
    max_output_chars: int = 1_000_000
    max_structure_depth: int = 32
    max_structure_items: int = 20_000
    max_redactions: int = 10_000
    max_path_chars: int = 32_767

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{field_name} must be numeric")
            if value <= 0:
                raise ValueError(f"{field_name} must be greater than zero")


DEFAULT_LIMITS: Final[Limits] = Limits()

# Module-level names are convenient for adapters that cannot carry a Limits
# instance while preserving a single authoritative value source.
MAX_GIT_OUTPUT_BYTES: Final[int] = DEFAULT_LIMITS.max_git_output_bytes
MAX_GIT_STATUS_ENTRIES: Final[int] = DEFAULT_LIMITS.max_git_status_entries
MAX_ARTIFACT_BYTES: Final[int] = DEFAULT_LIMITS.max_artifact_bytes
MAX_OUTPUT_CHARS: Final[int] = DEFAULT_LIMITS.max_output_chars
