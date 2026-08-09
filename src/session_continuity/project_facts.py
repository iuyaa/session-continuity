"""Bounded, read-only Git and explicitly named artifact facts.

No function in this module discovers files.  Git commands are fixed and run with
optional locks disabled; artifact functions inspect only paths supplied by the
caller and reject link-based containment bypasses by default.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    DEFAULT_LIMITS,
    ArtifactError,
    DomainCode,
    GitError,
    LimitExceededError,
    Limits,
)
from .paths import (
    FileIdentity,
    canonical_path,
    descriptor_identity,
    ensure_path_within,
    open_verified_readonly,
    verify_descriptor_identity,
)


_OBJECT_ID_RE = re.compile(r"[0-9a-fA-F]{40,64}\Z")
_CONFLICT_CODES = frozenset({"DD", "AU", "UD", "UA", "DU", "AA", "UU"})


@dataclass(frozen=True, slots=True)
class GitStatusCounts:
    """Path-free counts derived from Git porcelain status records."""

    entries: int = 0
    staged: int = 0
    unstaged: int = 0
    untracked: int = 0
    conflicted: int = 0

    @property
    def dirty(self) -> bool:
        """Return whether any tracked or untracked change is present."""

        return self.entries > 0


@dataclass(frozen=True, slots=True)
class GitFacts:
    """A bounded snapshot of repository identity and aggregate worktree state."""

    root: Path
    is_repository: bool
    head: str | None
    branch: str | None
    detached: bool
    status: GitStatusCounts


@dataclass(frozen=True, slots=True)
class NamedArtifactFacts:
    """Stat fields and optional SHA-256 for one caller-named regular file."""

    name: str
    path: Path
    size: int
    mtime_ns: int
    mode: int
    link_count: int
    identity: FileIdentity
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class _CommandResult:
    return_code: int
    output: bytes


def _run_bounded_command(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_output_bytes: int,
) -> _CommandResult:
    """Run a no-input command while enforcing time and combined-output bounds."""

    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            list(arguments),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            creationflags=creation_flags,
        )
    except FileNotFoundError as error:
        raise GitError(
            "Git executable was not found", code=DomainCode.GIT_UNAVAILABLE
        ) from error
    except OSError as error:
        raise GitError("Git command could not be started") from error

    chunks: list[bytes] = []
    total = 0
    exceeded = threading.Event()
    reader_error: list[BaseException] = []

    def pump() -> None:
        nonlocal total
        assert process.stdout is not None
        try:
            while True:
                chunk = process.stdout.read(16_384)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_output_bytes:
                    exceeded.set()
                    process.kill()
                    break
                chunks.append(chunk)
        except BaseException as error:  # retained and raised in the owner thread
            reader_error.append(error)
            process.kill()

    reader = threading.Thread(target=pump, name="bounded-command-reader", daemon=True)
    reader.start()
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        reader.join(timeout=1.0)
        if process.stdout is not None:
            process.stdout.close()
        raise GitError(
            "Git command exceeded the time limit",
            context={"timeout_seconds": timeout_seconds},
        ) from error

    reader.join(timeout=1.0)
    if process.stdout is not None:
        process.stdout.close()
    if reader.is_alive():
        process.kill()
        process.wait()
        raise GitError("Git output reader did not terminate")
    if reader_error:
        raise GitError("Git output could not be read") from reader_error[0]
    if exceeded.is_set():
        raise LimitExceededError(
            "Git output exceeds the byte limit",
            context={"limit": max_output_bytes},
        )
    return _CommandResult(return_code, b"".join(chunks))


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    git_executable: str,
    limits: Limits,
) -> _CommandResult:
    command = [git_executable, "--no-optional-locks", "-C", str(root), *arguments]
    return _run_bounded_command(
        command,
        cwd=root,
        timeout_seconds=limits.git_timeout_seconds,
        max_output_bytes=limits.max_git_output_bytes,
    )


def _decode_output(output: bytes) -> str:
    return output.decode(sys.getfilesystemencoding(), errors="surrogateescape")


def _single_line(output: bytes, *, fact_name: str, allow_empty: bool = False) -> str:
    text = _decode_output(output)
    if "\x00" in text:
        raise GitError(f"Git returned malformed {fact_name}")
    lines = text.splitlines()
    if not lines and allow_empty:
        return ""
    if len(lines) != 1 or (not lines[0] and not allow_empty):
        raise GitError(f"Git returned malformed {fact_name}")
    return lines[0]


def _parse_status(output: bytes, *, limits: Limits) -> GitStatusCounts:
    if not output:
        return GitStatusCounts()
    records = output.split(b"\x00")
    if records[-1] == b"":
        records.pop()

    entries = staged = unstaged = untracked = conflicted = 0
    index = 0
    while index < len(records):
        record = records[index]
        if len(record) < 3 or record[2:3] != b" ":
            raise GitError("Git returned malformed porcelain status")
        try:
            code = record[:2].decode("ascii")
        except UnicodeDecodeError as error:
            raise GitError("Git returned malformed porcelain status") from error

        entries += 1
        if entries > limits.max_git_status_entries:
            raise LimitExceededError(
                "Git status exceeds the entry limit",
                context={"limit": limits.max_git_status_entries},
            )
        if code == "??":
            untracked += 1
        elif code in _CONFLICT_CODES:
            conflicted += 1
        else:
            if code[0] not in {" ", "!", "?"}:
                staged += 1
            if code[1] not in {" ", "!", "?"}:
                unstaged += 1

        # In porcelain v1 -z, rename/copy entries carry a second NUL record for
        # the source path.  Consume it without retaining either path.
        if code[0] in {"R", "C"} or code[1] in {"R", "C"}:
            index += 1
            if index >= len(records):
                raise GitError("Git returned an incomplete rename status")
        index += 1

    return GitStatusCounts(entries, staged, unstaged, untracked, conflicted)


def collect_git_facts(
    root: os.PathLike[str] | str,
    *,
    git_executable: str = "git",
    limits: Limits = DEFAULT_LIMITS,
) -> GitFacts:
    """Collect fixed, bounded, read-only Git facts for ``root``.

    A non-repository is represented as data, not an exception.  Missing Git,
    command timeouts, malformed output, and exceeded limits remain stable domain
    errors because callers may need to distinguish those operational failures.
    No filenames, remotes, logs, diffs, or file contents are retained.
    """

    requested_root = canonical_path(root, strict=True, limits=limits)
    if not requested_root.is_dir():
        raise GitError("Git fact root is not a directory")

    probe = _git(
        requested_root,
        ("rev-parse", "--is-inside-work-tree", "--show-toplevel"),
        git_executable=git_executable,
        limits=limits,
    )
    if probe.return_code != 0:
        return GitFacts(
            root=requested_root,
            is_repository=False,
            head=None,
            branch=None,
            detached=False,
            status=GitStatusCounts(),
        )
    probe_text = _decode_output(probe.output)
    if "\x00" in probe_text:
        raise GitError("Git returned malformed repository facts")
    probe_lines = probe_text.splitlines()
    if len(probe_lines) != 2 or probe_lines[0] != "true":
        if len(probe_lines) == 1 and probe_lines[0] == "false":
            return GitFacts(
                root=requested_root,
                is_repository=False,
                head=None,
                branch=None,
                detached=False,
                status=GitStatusCounts(),
            )
        raise GitError("Git returned malformed repository facts")

    git_root = canonical_path(probe_lines[1], strict=True, limits=limits)
    ensure_path_within(requested_root, git_root, limits=limits)

    head_result = _git(
        git_root,
        ("rev-parse", "--verify", "HEAD"),
        git_executable=git_executable,
        limits=limits,
    )
    head: str | None
    if head_result.return_code == 0:
        head = _single_line(head_result.output, fact_name="HEAD").lower()
        if _OBJECT_ID_RE.fullmatch(head) is None:
            raise GitError("Git returned malformed HEAD")
    else:
        head = None

    branch_result = _git(
        git_root,
        ("symbolic-ref", "--quiet", "--short", "HEAD"),
        git_executable=git_executable,
        limits=limits,
    )
    if branch_result.return_code == 0:
        branch = _single_line(branch_result.output, fact_name="branch")
        detached = False
    elif branch_result.return_code == 1:
        branch = None
        detached = head is not None
    else:
        raise GitError(
            "Git branch query failed",
            context={"return_code": branch_result.return_code},
        )

    status_result = _git(
        git_root,
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=normal",
            "--",
            ".",
            ":(exclude).handoffs/**",
        ),
        git_executable=git_executable,
        limits=limits,
    )
    if status_result.return_code != 0:
        raise GitError(
            "Git status query failed",
            context={"return_code": status_result.return_code},
        )
    status_counts = _parse_status(status_result.output, limits=limits)
    return GitFacts(git_root, True, head, branch, detached, status_counts)


def _validate_artifact_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ArtifactError(
            "artifact name must be non-empty", code=DomainCode.INVALID_ARGUMENT
        )
    if len(name) > 128 or any(ord(char) < 32 for char in name):
        raise ArtifactError(
            "artifact name is invalid", code=DomainCode.INVALID_ARGUMENT
        )
    return name


def _artifact_path(
    path: os.PathLike[str] | str,
    *,
    root: Path,
    limits: Limits,
) -> Path:
    try:
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
            raise ValueError("artifact path must be non-empty text")
        supplied = Path(raw_path)
        candidate = supplied if supplied.is_absolute() else root / supplied
        # Canonical containment is a validation only.  Preserve the lexical name
        # so open_verified_readonly can still observe and reject an in-root link.
        ensure_path_within(candidate, root, allow_equal=False, limits=limits)
        return Path(os.path.abspath(candidate))
    except Exception as error:
        if isinstance(error, ArtifactError):
            raise
        raise ArtifactError("artifact path is not a contained file") from error


def stat_named_artifact(
    name: str,
    path: os.PathLike[str] | str,
    *,
    root: os.PathLike[str] | str,
    reject_hardlinks: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> NamedArtifactFacts:
    """Stat one explicitly named artifact through a verified descriptor."""

    artifact_name = _validate_artifact_name(name)
    canonical_root = canonical_path(root, strict=True, limits=limits)
    artifact_path = _artifact_path(path, root=canonical_root, limits=limits)
    try:
        with open_verified_readonly(
            artifact_path,
            canonical_root,
            reject_hardlinks=reject_hardlinks,
            limits=limits,
        ) as stream:
            identity = descriptor_identity(stream)
    except Exception as error:
        if isinstance(error, (ArtifactError, LimitExceededError)):
            raise
        raise ArtifactError("artifact could not be safely stat'ed") from error
    return NamedArtifactFacts(
        artifact_name,
        artifact_path,
        identity.size,
        identity.mtime_ns,
        identity.mode,
        identity.link_count,
        identity,
    )


def hash_named_artifact(
    name: str,
    path: os.PathLike[str] | str,
    *,
    root: os.PathLike[str] | str,
    reject_hardlinks: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> NamedArtifactFacts:
    """SHA-256 one explicitly named artifact with size and identity bounds."""

    artifact_name = _validate_artifact_name(name)
    canonical_root = canonical_path(root, strict=True, limits=limits)
    artifact_path = _artifact_path(path, root=canonical_root, limits=limits)
    try:
        with open_verified_readonly(
            artifact_path,
            canonical_root,
            reject_hardlinks=reject_hardlinks,
            limits=limits,
        ) as stream:
            initial = descriptor_identity(stream)
            if initial.size > limits.max_artifact_bytes:
                raise LimitExceededError(
                    "artifact exceeds the hash byte limit",
                    context={"limit": limits.max_artifact_bytes},
                )
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = stream.read(limits.artifact_chunk_bytes)
                if not chunk:
                    break
                total += len(chunk)
                if total > limits.max_artifact_bytes:
                    raise LimitExceededError(
                        "artifact exceeds the hash byte limit",
                        context={"limit": limits.max_artifact_bytes},
                    )
                digest.update(chunk)
            final = verify_descriptor_identity(stream, initial, require_unchanged=True)
            if total != final.size:
                raise ArtifactError(
                    "artifact changed while hashing", code=DomainCode.ARTIFACT_CHANGED
                )
    except (ArtifactError, LimitExceededError):
        raise
    except Exception as error:
        raise ArtifactError("artifact could not be safely hashed") from error

    return NamedArtifactFacts(
        artifact_name,
        artifact_path,
        final.size,
        final.mtime_ns,
        final.mode,
        final.link_count,
        final,
        digest.hexdigest(),
    )


def collect_named_artifacts(
    artifacts: Mapping[str, os.PathLike[str] | str],
    *,
    root: os.PathLike[str] | str,
    include_hash: bool = True,
    reject_hardlinks: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> tuple[NamedArtifactFacts, ...]:
    """Inspect only the explicitly named artifact mapping supplied by the caller."""

    if not isinstance(artifacts, Mapping):
        raise ArtifactError(
            "artifacts must be an explicit name-to-path mapping",
            code=DomainCode.INVALID_ARGUMENT,
        )
    if len(artifacts) > limits.max_artifacts:
        raise LimitExceededError(
            "artifact count exceeds the configured limit",
            context={"limit": limits.max_artifacts},
        )
    names = tuple(_validate_artifact_name(name) for name in artifacts)
    operation = hash_named_artifact if include_hash else stat_named_artifact
    return tuple(
        operation(
            name,
            artifacts[name],
            root=root,
            reject_hardlinks=reject_hardlinks,
            limits=limits,
        )
        for name in sorted(names)
    )
