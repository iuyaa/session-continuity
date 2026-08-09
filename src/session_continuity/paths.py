"""Canonical project-root and race-aware filesystem path primitives.

Security-sensitive callers should validate containment, reject links, open a file
read-only, and then compare descriptor identity.  Those operations are kept here
so artifact readers do not each invent subtly different path policies.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import BinaryIO, Protocol, runtime_checkable

from .contracts import (
    DEFAULT_LIMITS,
    DomainCode,
    FilesystemError,
    InvalidInputError,
    Limits,
    PathSafetyError,
)


_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
        "COM¹",
        "COM²",
        "COM³",
        "LPT¹",
        "LPT²",
        "LPT³",
    }
)
_WINDOWS_INVALID_CHARS = frozenset('<>"|?*')
_WINDOWS_DEVICE_PREFIXES = ("\\\\?\\", "\\\\.\\", "\\??\\")
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@runtime_checkable
class HasFileDescriptor(Protocol):
    """Protocol implemented by binary file objects accepted by identity helpers."""

    def fileno(self) -> int:
        """Return an open operating-system file descriptor."""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Stable identity and version fields captured from ``stat``/``fstat``.

    On Windows, ``device`` and ``inode`` correspond to volume and file identity.
    ``same_object`` is suitable for path/descriptor race checks; ``same_version``
    additionally detects an object modified while it was being read.
    """

    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    link_count: int

    def same_object(self, other: "FileIdentity") -> bool:
        """Return whether two snapshots identify the same filesystem object."""

        return self.device == other.device and self.inode == other.inode

    def same_version(self, other: "FileIdentity") -> bool:
        """Return whether identity, type, size, and timestamps are unchanged."""

        return (
            self.same_object(other)
            and stat.S_IFMT(self.mode) == stat.S_IFMT(other.mode)
            and self.size == other.size
            and self.mtime_ns == other.mtime_ns
            and self.ctime_ns == other.ctime_ns
        )


def _path_text(path: os.PathLike[str] | str, *, limits: Limits) -> str:
    try:
        text = os.fspath(path)
    except TypeError as error:
        raise InvalidInputError("path must be a string or path-like value") from error
    if not isinstance(text, str):
        raise InvalidInputError("byte paths are not accepted")
    if not text:
        raise InvalidInputError("path must not be empty")
    if "\x00" in text:
        raise InvalidInputError("path must not contain a NUL character")
    if ".." in text.replace("\\", "/").split("/"):
        raise PathSafetyError(
            "path traversal components are not accepted",
            code=DomainCode.PATH_OUTSIDE_ROOT,
        )
    if len(text) > limits.max_path_chars:
        raise PathSafetyError(
            "path exceeds the configured length limit",
            code=DomainCode.UNSAFE_PATH,
            context={"limit": limits.max_path_chars},
        )
    return text


def validate_windows_path_syntax(
    path: os.PathLike[str] | str,
    *,
    require_absolute: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> PureWindowsPath:
    """Validate ordinary Win32 path syntax without touching the filesystem.

    Device namespaces, alternate data streams, traversal components, reserved
    DOS names, trailing spaces/dots, and drive-relative paths are rejected.  UNC
    paths are accepted only when both a server and share are present.
    """

    text = _path_text(path, limits=limits)
    normalized = text.replace("/", "\\")
    if normalized.startswith(_WINDOWS_DEVICE_PREFIXES):
        raise PathSafetyError("Windows device namespace paths are not accepted")

    candidate = PureWindowsPath(normalized)
    if require_absolute and not candidate.is_absolute():
        raise PathSafetyError("Windows path must be drive-absolute or UNC-absolute")
    if candidate.drive and not candidate.root:
        raise PathSafetyError("drive-relative Windows paths are not accepted")

    anchor_components: tuple[str, ...] = ()
    if candidate.drive.startswith("\\\\"):
        unc_parts = tuple(part for part in candidate.drive[2:].split("\\") if part)
        if len(unc_parts) != 2:
            raise PathSafetyError("UNC path must contain a server and share")
        anchor_components = unc_parts

    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for component in (*anchor_components, *parts):
        if component in {".", ".."}:
            raise PathSafetyError("Windows traversal components are not accepted")
        if not component:
            continue
        if component[-1] in {" ", "."}:
            raise PathSafetyError("Windows path components cannot end in space or dot")
        if any(ord(char) < 32 for char in component):
            raise PathSafetyError("Windows path components cannot contain controls")
        if ":" in component or any(char in _WINDOWS_INVALID_CHARS for char in component):
            raise PathSafetyError("Windows path contains an invalid component")
        basename = component.split(".", 1)[0].rstrip(" .").upper()
        if basename in _WINDOWS_RESERVED_NAMES:
            raise PathSafetyError("Windows path contains a reserved device name")
    return candidate


def is_valid_windows_path_syntax(
    path: os.PathLike[str] | str,
    *,
    require_absolute: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> bool:
    """Return a boolean form of :func:`validate_windows_path_syntax`."""

    try:
        validate_windows_path_syntax(
            path, require_absolute=require_absolute, limits=limits
        )
    except (InvalidInputError, PathSafetyError):
        return False
    return True


def windows_path_is_within(
    path: os.PathLike[str] | str,
    root: os.PathLike[str] | str,
    *,
    allow_equal: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> bool:
    """Compare absolute Windows paths with case-insensitive component semantics.

    This is a syntax-level helper and intentionally does not claim to resolve
    junctions or symlinks.  Filesystem callers should additionally use
    :func:`ensure_path_within` and :func:`ensure_no_reparse_or_symlink`.
    """

    try:
        candidate = validate_windows_path_syntax(path, limits=limits)
        boundary = validate_windows_path_syntax(root, limits=limits)
    except (InvalidInputError, PathSafetyError):
        return False

    if candidate.drive.casefold() != boundary.drive.casefold():
        return False
    candidate_parts = tuple(part.casefold() for part in candidate.parts[1:])
    boundary_parts = tuple(part.casefold() for part in boundary.parts[1:])
    if len(candidate_parts) < len(boundary_parts):
        return False
    if candidate_parts[: len(boundary_parts)] != boundary_parts:
        return False
    return allow_equal or len(candidate_parts) > len(boundary_parts)


def canonical_path(
    path: os.PathLike[str] | str,
    *,
    strict: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> Path:
    """Return a local absolute canonical path with stable domain errors."""

    text = _path_text(path, limits=limits)
    if os.name == "nt":
        validate_windows_path_syntax(text, require_absolute=False, limits=limits)
    try:
        return Path(os.path.abspath(text)).resolve(strict=strict)
    except FileNotFoundError as error:
        raise PathSafetyError(
            "path does not exist", code=DomainCode.PATH_NOT_FOUND
        ) from error
    except (OSError, RuntimeError) as error:
        raise FilesystemError("path canonicalization failed") from error


def is_path_within(
    path: os.PathLike[str] | str,
    root: os.PathLike[str] | str,
    *,
    allow_equal: bool = True,
    strict: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> bool:
    """Return whether a canonical local path is contained by a canonical root."""

    try:
        candidate = canonical_path(path, strict=strict, limits=limits)
        boundary = canonical_path(root, strict=True, limits=limits)
        relative = candidate.relative_to(boundary)
    except (InvalidInputError, PathSafetyError, FilesystemError, ValueError):
        return False
    return allow_equal or bool(relative.parts)


def ensure_path_within(
    path: os.PathLike[str] | str,
    root: os.PathLike[str] | str,
    *,
    allow_equal: bool = True,
    strict: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> Path:
    """Return a canonical contained path or raise ``PATH_OUTSIDE_ROOT``."""

    candidate = canonical_path(path, strict=strict, limits=limits)
    boundary = canonical_path(root, strict=True, limits=limits)
    try:
        relative = candidate.relative_to(boundary)
    except ValueError as error:
        raise PathSafetyError(
            "path is outside the allowed root", code=DomainCode.PATH_OUTSIDE_ROOT
        ) from error
    if not allow_equal and not relative.parts:
        raise PathSafetyError(
            "path must be below the allowed root", code=DomainCode.PATH_OUTSIDE_ROOT
        )
    return candidate


def _lexical_contained_path(
    path: os.PathLike[str] | str,
    root: os.PathLike[str] | str,
    *,
    limits: Limits,
) -> tuple[Path, Path]:
    boundary = canonical_path(root, strict=True, limits=limits)
    text = _path_text(path, limits=limits)
    supplied = Path(text)
    candidate = Path(os.path.abspath(supplied if supplied.is_absolute() else boundary / supplied))
    try:
        common = Path(os.path.commonpath((str(boundary), str(candidate))))
    except ValueError as error:
        raise PathSafetyError(
            "path is outside the allowed root", code=DomainCode.PATH_OUTSIDE_ROOT
        ) from error
    if os.path.normcase(str(common)) != os.path.normcase(str(boundary)):
        raise PathSafetyError(
            "path is outside the allowed root", code=DomainCode.PATH_OUTSIDE_ROOT
        )
    return candidate, boundary


def _lstat(path: os.PathLike[str] | str) -> os.stat_result:
    try:
        return os.stat(path, follow_symlinks=False)
    except FileNotFoundError as error:
        raise PathSafetyError(
            "path does not exist", code=DomainCode.PATH_NOT_FOUND
        ) from error
    except OSError as error:
        raise FilesystemError("path stat failed") from error


def stat_is_reparse_point(snapshot: os.stat_result) -> bool:
    """Return whether a stat snapshot represents a Windows reparse point."""

    attributes = int(getattr(snapshot, "st_file_attributes", 0))
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def is_reparse_point(path: os.PathLike[str] | str) -> bool:
    """Inspect a path itself, rather than its target, for a reparse attribute."""

    snapshot = _lstat(path)
    return stat_is_reparse_point(snapshot)


def is_symlink(path: os.PathLike[str] | str) -> bool:
    """Return whether a path itself is a symbolic link."""

    return stat.S_ISLNK(_lstat(path).st_mode)


def stat_is_hardlinked_regular_file(snapshot: os.stat_result) -> bool:
    """Return whether a stat snapshot is a regular file with multiple links."""

    return stat.S_ISREG(snapshot.st_mode) and snapshot.st_nlink > 1


def is_hardlinked_file(path: os.PathLike[str] | str) -> bool:
    """Return whether a non-followed path is a multiply linked regular file."""

    return stat_is_hardlinked_regular_file(_lstat(path))


def ensure_no_reparse_or_symlink(
    path: os.PathLike[str] | str,
    root: os.PathLike[str] | str,
    *,
    limits: Limits = DEFAULT_LIMITS,
) -> Path:
    """Reject symlink/reparse components between ``root`` and ``path``.

    This checks components directly and does not use a directory walk or glob.
    The returned path is lexical; a descriptor identity check is still required
    after opening to close the check/open race.
    """

    candidate, boundary = _lexical_contained_path(path, root, limits=limits)
    try:
        relative = candidate.relative_to(boundary)
    except ValueError as error:
        raise PathSafetyError(
            "path is outside the allowed root", code=DomainCode.PATH_OUTSIDE_ROOT
        ) from error

    current = boundary
    for component in relative.parts:
        current = current / component
        snapshot = _lstat(current)
        if stat.S_ISLNK(snapshot.st_mode) or stat_is_reparse_point(snapshot):
            raise PathSafetyError("path crosses a symlink or reparse point")
    return candidate


def identity_from_stat(snapshot: os.stat_result) -> FileIdentity:
    """Convert a platform stat result into a comparable immutable identity."""

    return FileIdentity(
        device=int(snapshot.st_dev),
        inode=int(snapshot.st_ino),
        mode=int(snapshot.st_mode),
        size=int(snapshot.st_size),
        mtime_ns=int(snapshot.st_mtime_ns),
        ctime_ns=int(snapshot.st_ctime_ns),
        link_count=int(snapshot.st_nlink),
    )


def descriptor_identity(descriptor: int | HasFileDescriptor) -> FileIdentity:
    """Capture identity from an already-open descriptor or binary file object."""

    fd = descriptor if isinstance(descriptor, int) else descriptor.fileno()
    try:
        return identity_from_stat(os.fstat(fd))
    except OSError as error:
        raise FilesystemError("descriptor stat failed") from error


def path_identity(
    path: os.PathLike[str] | str, *, follow_symlinks: bool = False
) -> FileIdentity:
    """Capture identity from a path, non-following by default."""

    try:
        return identity_from_stat(os.stat(path, follow_symlinks=follow_symlinks))
    except FileNotFoundError as error:
        raise PathSafetyError(
            "path does not exist", code=DomainCode.PATH_NOT_FOUND
        ) from error
    except OSError as error:
        raise FilesystemError("path stat failed") from error


def verify_descriptor_identity(
    descriptor: int | HasFileDescriptor,
    expected: FileIdentity,
    *,
    require_unchanged: bool = False,
) -> FileIdentity:
    """Verify descriptor identity against a prior path/descriptor snapshot."""

    actual = descriptor_identity(descriptor)
    matches = expected.same_version(actual) if require_unchanged else expected.same_object(actual)
    if not matches:
        raise PathSafetyError("descriptor identity does not match the expected file")
    return actual


def open_verified_readonly(
    path: os.PathLike[str] | str,
    root: os.PathLike[str] | str,
    *,
    reject_hardlinks: bool = True,
    limits: Limits = DEFAULT_LIMITS,
) -> BinaryIO:
    """Open a contained regular file and verify path-to-descriptor identity.

    Every path component is checked for symlink/reparse behavior.  The final file
    is lstat'ed before and after ``open`` and compared with ``fstat``.  Hardlinks
    are rejected by default because containment of one name does not establish
    containment of every name for the same object.
    """

    candidate = ensure_no_reparse_or_symlink(path, root, limits=limits)
    before_stat = _lstat(candidate)
    before = identity_from_stat(before_stat)
    if not stat.S_ISREG(before.mode):
        raise PathSafetyError("path is not a regular file")
    if reject_hardlinks and before.link_count > 1:
        raise PathSafetyError("hardlinked files are not accepted")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(candidate, flags)
    except FileNotFoundError as error:
        raise PathSafetyError(
            "path does not exist", code=DomainCode.PATH_NOT_FOUND
        ) from error
    except OSError as error:
        raise FilesystemError("read-only file open failed") from error

    try:
        opened_stat = os.fstat(fd)
        opened = identity_from_stat(opened_stat)
        after_stat = _lstat(candidate)
        after = identity_from_stat(after_stat)
        if not before.same_object(opened) or not opened.same_object(after):
            raise PathSafetyError("file identity changed while opening")
        if not stat.S_ISREG(opened.mode):
            raise PathSafetyError("opened descriptor is not a regular file")
        if stat_is_reparse_point(after_stat):
            raise PathSafetyError("opened path became a reparse point")
        if reject_hardlinks and (opened.link_count > 1 or after.link_count > 1):
            raise PathSafetyError("hardlinked files are not accepted")
        return os.fdopen(fd, "rb", closefd=True)
    except BaseException:
        os.close(fd)
        raise


def _run_git_toplevel(
    cwd: Path,
    *,
    git_executable: str,
    limits: Limits,
) -> str | None:
    """Run one bounded, read-only Git query, returning decoded output on success."""

    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            [git_executable, "--no-optional-locks", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            creationflags=creation_flags,
        )
    except (FileNotFoundError, OSError):
        return None

    chunks: list[bytes] = []
    size = 0
    exceeded = threading.Event()
    reader_failed = threading.Event()

    def read_output() -> None:
        nonlocal size
        assert process.stdout is not None
        try:
            while True:
                chunk = process.stdout.read(8_192)
                if not chunk:
                    break
                size += len(chunk)
                if size > limits.max_git_output_bytes:
                    exceeded.set()
                    process.kill()
                    break
                chunks.append(chunk)
        except OSError:
            reader_failed.set()
            process.kill()

    reader = threading.Thread(target=read_output, name="git-root-reader", daemon=True)
    reader.start()
    try:
        return_code = process.wait(timeout=limits.git_timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        reader.join(timeout=1.0)
        if process.stdout is not None:
            process.stdout.close()
        return None
    reader.join(timeout=1.0)
    if process.stdout is not None:
        process.stdout.close()
    if reader.is_alive() or reader_failed.is_set() or exceeded.is_set() or return_code != 0:
        if process.poll() is None:
            process.kill()
            process.wait()
        return None
    return b"".join(chunks).decode(sys.getfilesystemencoding(), errors="surrogateescape")


def resolve_project_root(
    invocation_cwd: os.PathLike[str] | str,
    *,
    git_executable: str = "git",
    limits: Limits = DEFAULT_LIMITS,
) -> Path:
    """Resolve invocation CWD to a valid canonical Git top-level, else CWD.

    Git output is accepted only when it is one non-empty path naming an existing
    directory that canonically contains the invocation directory.  Any missing
    executable, timeout, nonzero exit, oversized output, malformed output, or
    invalid top-level fails closed to the canonical invocation directory.
    """

    cwd = canonical_path(invocation_cwd, strict=True, limits=limits)
    if not cwd.is_dir():
        raise PathSafetyError("invocation CWD is not a directory")

    output = _run_git_toplevel(cwd, git_executable=git_executable, limits=limits)
    if output is None or "\x00" in output:
        return cwd
    lines = output.splitlines()
    if len(lines) != 1 or not lines[0]:
        return cwd
    try:
        top_level = canonical_path(lines[0], strict=True, limits=limits)
    except (InvalidInputError, PathSafetyError, FilesystemError):
        return cwd
    if not top_level.is_dir() or not is_path_within(cwd, top_level, limits=limits):
        return cwd
    return top_level


def invocation_cwd_to_project_root(
    invocation_cwd: os.PathLike[str] | str,
    *,
    git_executable: str = "git",
    limits: Limits = DEFAULT_LIMITS,
) -> Path:
    """Named adapter for :func:`resolve_project_root`."""

    return resolve_project_root(
        invocation_cwd, git_executable=git_executable, limits=limits
    )
