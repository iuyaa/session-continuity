"""Two-stage, counted, fail-closed redaction for report data and output.

Stage one understands JSON-like structure and suppresses values under sensitive
keys.  Stage two scans every string (and the final serialized output) for values
that do not depend on field names.  Output is returned only after a residual scan
finds no known sensitive pattern.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Generic, TypeVar

from .contracts import (
    DEFAULT_LIMITS,
    DomainCode,
    InvalidInputError,
    LimitExceededError,
    Limits,
    RedactionError,
)


T = TypeVar("T")


class RedactionCategory(StrEnum):
    """Stable categories used by placeholders and count reports."""

    PRIVATE_KEY = "private_key"
    CREDENTIAL = "credential"
    SECRET = "secret"
    URL_USERINFO = "url_userinfo"
    PRIVATE_URL = "private_url"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    FILESYSTEM_PATH = "filesystem_path"


@dataclass(frozen=True, slots=True)
class RedactionCounts:
    """Immutable category counts for one or more redaction stages."""

    counts: Mapping[RedactionCategory, int]

    def __post_init__(self) -> None:
        normalized: dict[RedactionCategory, int] = {}
        for category in RedactionCategory:
            count = int(self.counts.get(category, 0))
            if count < 0:
                raise ValueError("redaction counts cannot be negative")
            normalized[category] = count
        object.__setattr__(self, "counts", MappingProxyType(normalized))

    def __getitem__(self, category: RedactionCategory | str) -> int:
        """Return one category count, accepting enum or stable string name."""

        return self.counts[RedactionCategory(category)]

    @property
    def total(self) -> int:
        """Return the total number of replacements across all categories."""

        return sum(self.counts.values())

    def as_dict(self) -> dict[str, int]:
        """Return string-keyed counts in enum declaration order."""

        return {category.value: self.counts[category] for category in RedactionCategory}

    def merged(self, other: "RedactionCounts") -> "RedactionCounts":
        """Add counts from two sequential stages."""

        return RedactionCounts(
            {
                category: self.counts[category] + other.counts[category]
                for category in RedactionCategory
            }
        )


@dataclass(frozen=True, slots=True)
class RedactionResult(Generic[T]):
    """A redacted value paired with auditable replacement counts."""

    value: T
    counts: RedactionCounts


@dataclass(frozen=True, slots=True)
class _TextPattern:
    category: RedactionCategory
    regex: re.Pattern[str]
    replacement: str | Callable[[re.Match[str]], str]


_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_PRIVATE_KEY_MARKER_RE = re.compile(
    r"-----(?:BEGIN|END)(?: [A-Z0-9]+)? PRIVATE KEY-----", re.IGNORECASE
)
_AUTHORIZATION_HEADER_RE = re.compile(
    r"(?im)(?P<prefix>\bauthorization\s*:\s*)(?P<value>(?!\[REDACTED:)\S[^\r\n]*)"
)
_QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>[\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth(?:orization)?|bearer|password|passwd|pwd|secret|session[_-]?token|cookie)"
    r"[\"']?\s*[:=]\s*)(?P<quote>[\"'])(?P<value>(?!\[REDACTED:).*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_UNQUOTED_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth(?:orization)?|bearer|password|passwd|pwd|secret|session[_-]?token|cookie)"
    r"\b\s*[:=]\s*)(?P<value>(?!\[REDACTED:)[^\s,;\r\n}][^,;\r\n}]*)",
    re.IGNORECASE,
)
_AUTH_SCHEME_RE = re.compile(
    r"\b(?P<scheme>Bearer|Basic)\s+(?P<value>(?!\[REDACTED:)[A-Za-z0-9._~+/=-]{4,})",
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(
    r"\b(?P<scheme>[a-z][a-z0-9+.-]*://)(?!\[REDACTED:)"
    r"(?P<userinfo>[^/\s:@]+:[^/\s@]+)@",
    re.IGNORECASE,
)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_TOKEN_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|"
    r"sk_live_[A-Za-z0-9]{16,}|"
    r"npm_[A-Za-z0-9]{30,}"
    r")(?![A-Za-z0-9_-])"
)
_HIGH_ENTROPY_RE = re.compile(
    r"(?<![A-Za-z0-9_+/-])[A-Za-z0-9_+/-]{32,256}={0,2}(?![A-Za-z0-9_+/=-])"
)
_RELATIVE_FILE_SEGMENT_RE = re.compile(r"[A-Za-z0-9._-]+")
_RELATIVE_DIRECTORY_SEGMENT_RE = re.compile(r"[a-z][a-z_-]{0,23}")
_RELATIVE_FILE_EXTENSION_RE = re.compile(r"[A-Za-z0-9]{1,16}")
_SAFE_CAMEL_SOURCE_STEM_RE = re.compile(r"(?:[A-Z][a-z]{2,}){2,8}")
_SAFE_RELATIVE_LAYOUT_PREFIXES = (
    ("frontend", "src", "modules"),
    ("frontend", "src", "components"),
    ("rpa_service",),
    ("scripts",),
    ("tests",),
    ("app",),
    ("src",),
    ("web",),
)
_SAFE_SOURCE_EXTENSIONS = frozenset(
    {
        "c",
        "cpp",
        "cs",
        "css",
        "go",
        "h",
        "hpp",
        "html",
        "java",
        "js",
        "jsx",
        "kt",
        "php",
        "py",
        "pyi",
        "rb",
        "rs",
        "scss",
        "sh",
        "swift",
        "ts",
        "tsx",
        "vue",
    }
)
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
)
_PHONE_RE = re.compile(
    r"(?<!\w)(?:\+\d(?:[ .()-]*\d){7,14}|"
    r"\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}|1[3-9]\d{9})(?!\w)"
)
_PRIVATE_URL_RE = re.compile(
    r"\bhttps?://(?:[^/\s@]+@)?"
    r"(?P<host>\[[0-9A-Fa-f:%._-]+\]|[^/:\s?#]+)"
    r"(?::\d{1,5})?(?:/[^\s<>'\"]*)?",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9-])"
)
_IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?:%[A-Za-z0-9_.-]+)?(?![0-9A-Fa-f:])"
)
_WINDOWS_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z]:[\\/](?:[^\s<>:\"|?*]+[\\/])*"
    r"[^\s<>:\"|?*,;)}\]]*|\\\\[^\\/\s]+[\\/][^\s,;)}\]]+)"
)
_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9:/])/(?:[^/\s,;)}\]]+/)+[^/\s,;)}\]]+"
)
_HOME_PATH_RE = re.compile(r"(?<!\w)~[\\/][^\s,;)}\]]+")


def _placeholder(category: RedactionCategory) -> str:
    return f"[REDACTED:{category.value}]"


def _replace_authorization_header(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{_placeholder(RedactionCategory.CREDENTIAL)}"


def _replace_quoted_assignment(match: re.Match[str]) -> str:
    return (
        f"{match.group('prefix')}{match.group('quote')}"
        f"{_placeholder(RedactionCategory.CREDENTIAL)}{match.group('quote')}"
    )


def _replace_unquoted_assignment(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{_placeholder(RedactionCategory.CREDENTIAL)}"


def _replace_auth_scheme(match: re.Match[str]) -> str:
    return f"{match.group('scheme')} {_placeholder(RedactionCategory.CREDENTIAL)}"


def _replace_url_userinfo(match: re.Match[str]) -> str:
    return f"{match.group('scheme')}{_placeholder(RedactionCategory.URL_USERINFO)}@"


_TEXT_PATTERNS = (
    _TextPattern(
        RedactionCategory.PRIVATE_KEY,
        _PRIVATE_KEY_RE,
        _placeholder(RedactionCategory.PRIVATE_KEY),
    ),
    _TextPattern(
        RedactionCategory.CREDENTIAL,
        _AUTHORIZATION_HEADER_RE,
        _replace_authorization_header,
    ),
    _TextPattern(
        RedactionCategory.CREDENTIAL,
        _QUOTED_ASSIGNMENT_RE,
        _replace_quoted_assignment,
    ),
    _TextPattern(
        RedactionCategory.CREDENTIAL,
        _UNQUOTED_ASSIGNMENT_RE,
        _replace_unquoted_assignment,
    ),
    _TextPattern(RedactionCategory.CREDENTIAL, _AUTH_SCHEME_RE, _replace_auth_scheme),
    _TextPattern(RedactionCategory.URL_USERINFO, _URL_USERINFO_RE, _replace_url_userinfo),
    _TextPattern(
        RedactionCategory.CREDENTIAL,
        _JWT_RE,
        _placeholder(RedactionCategory.CREDENTIAL),
    ),
    _TextPattern(
        RedactionCategory.CREDENTIAL,
        _TOKEN_PREFIX_RE,
        _placeholder(RedactionCategory.CREDENTIAL),
    ),
    _TextPattern(
        RedactionCategory.PHONE,
        _PHONE_RE,
        _placeholder(RedactionCategory.PHONE),
    ),
    _TextPattern(RedactionCategory.EMAIL, _EMAIL_RE, _placeholder(RedactionCategory.EMAIL)),
    _TextPattern(
        RedactionCategory.FILESYSTEM_PATH,
        _WINDOWS_PATH_RE,
        _placeholder(RedactionCategory.FILESYSTEM_PATH),
    ),
    _TextPattern(
        RedactionCategory.FILESYSTEM_PATH,
        _POSIX_PATH_RE,
        _placeholder(RedactionCategory.FILESYSTEM_PATH),
    ),
    _TextPattern(
        RedactionCategory.FILESYSTEM_PATH,
        _HOME_PATH_RE,
        _placeholder(RedactionCategory.FILESYSTEM_PATH),
    ),
)

_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_\-.])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|"
    r"auth(?:orization)?|password|passwd|pwd|secret|private[_-]?key|cookie|"
    r"session[_-]?token)(?:$|[_\-.])",
    re.IGNORECASE,
)


def _key_category(key: str) -> RedactionCategory | None:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    match = _SENSITIVE_KEY_RE.search(normalized)
    if match is None:
        return None
    lowered = match.group(0).lower()
    if "private" in lowered and "key" in lowered:
        return RedactionCategory.PRIVATE_KEY
    if "secret" in lowered:
        return RedactionCategory.SECRET
    return RedactionCategory.CREDENTIAL


def _private_url_match(match: re.Match[str]) -> bool:
    host = match.group("host").strip("[]").split("%", 1)[0].casefold().rstrip(".")
    if host == "localhost" or host.endswith((".localhost", ".internal", ".local", ".lan", ".home", ".corp")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


def _replace_private_urls(
    text: str, counts: Counter[RedactionCategory]
) -> str:
    def replace(match: re.Match[str]) -> str:
        if not _private_url_match(match):
            return match.group(0)
        counts[RedactionCategory.PRIVATE_URL] += 1
        return _placeholder(RedactionCategory.PRIVATE_URL)

    return _PRIVATE_URL_RE.sub(replace, text)


def _shannon_entropy(candidate: str) -> float:
    frequencies = Counter(candidate)
    return -sum(
        (count / len(candidate)) * math.log2(count / len(candidate))
        for count in frequencies.values()
    )


def _looks_high_entropy(candidate: str) -> bool:
    if _UUID_RE.fullmatch(candidate) or re.fullmatch(r"[0-9A-Fa-f]+", candidate):
        return False
    classes = sum(
        (
            any(character.islower() for character in candidate),
            any(character.isupper() for character in candidate),
            any(character.isdigit() for character in candidate),
            any(not character.isalnum() for character in candidate),
        )
    )
    if classes < 2:
        return False
    return _shannon_entropy(candidate) >= 4.0


def _relative_file_character(character: str) -> bool:
    return character.isascii() and (
        character.isalnum() or character in {".", "_", "-", "/", "\\"}
    )


def _safe_relative_directories(parts: list[str]) -> bool:
    for prefix in _SAFE_RELATIVE_LAYOUT_PREFIXES:
        if tuple(parts[: len(prefix)]) != prefix:
            continue
        dynamic = parts[len(prefix) :]
        if len(dynamic) > 2 or any(
            len(part) > 12 or not _RELATIVE_DIRECTORY_SEGMENT_RE.fullmatch(part)
            for part in dynamic
        ):
            return False
        joined = "".join(dynamic)
        return len(joined) < 16 or _shannon_entropy(joined) < 3.5
    return False


def _is_safe_relative_file_match(text: str, match: re.Match[str]) -> bool:
    start = match.start()
    while start > 0 and _relative_file_character(text[start - 1]):
        start -= 1
    end = match.end()
    while end < len(text) and _relative_file_character(text[end]):
        end += 1

    token = text[start:end]
    if not token or len(token) > 512 or token.startswith(("/", "\\")):
        return False
    if "/" in token and "\\" in token:
        return False
    normalized = token.replace("\\", "/")
    parts = normalized.split("/")
    if len(parts) < 2 or any(
        part in {"", ".", ".."} or not _RELATIVE_FILE_SEGMENT_RE.fullmatch(part)
        for part in parts
    ):
        return False

    filename = parts[-1]
    stem, separator, extension = filename.rpartition(".")
    if (
        not separator
        or not stem
        or not _RELATIVE_FILE_SEGMENT_RE.fullmatch(stem)
        or not _RELATIVE_FILE_EXTENSION_RE.fullmatch(extension)
    ):
        return False
    if not _safe_relative_directories(parts[:-1]):
        return False
    if (
        len(stem) >= 32
        or extension.casefold() not in _SAFE_SOURCE_EXTENSIONS
        or not _SAFE_CAMEL_SOURCE_STEM_RE.fullmatch(stem)
        or _shannon_entropy(stem) >= 4.0
    ):
        return False
    extension_start = start + normalized.rfind(".")
    return match.end() == extension_start


def _replace_high_entropy(
    text: str, counts: Counter[RedactionCategory]
) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if not _looks_high_entropy(candidate) or _is_safe_relative_file_match(
            text, match
        ):
            return candidate
        counts[RedactionCategory.SECRET] += 1
        return _placeholder(RedactionCategory.SECRET)

    return _HIGH_ENTROPY_RE.sub(replace, text)


def _replace_ip_candidates(
    text: str, counts: Counter[RedactionCategory]
) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        address = candidate.split("%", 1)[0]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return candidate
        counts[RedactionCategory.IP_ADDRESS] += 1
        return _placeholder(RedactionCategory.IP_ADDRESS)

    text = _IPV4_CANDIDATE_RE.sub(replace, text)
    return _IPV6_CANDIDATE_RE.sub(replace, text)


def _apply_text_patterns(
    text: str,
    *,
    limits: Limits,
    verify_residual: bool,
) -> tuple[str, Counter[RedactionCategory]]:
    if not isinstance(text, str):
        raise InvalidInputError("redaction input must be text")
    if len(text) > limits.max_output_chars:
        raise LimitExceededError(
            "redaction input exceeds the character limit",
            context={"limit": limits.max_output_chars},
        )
    if "\x00" in text:
        raise RedactionError(
            "redaction input contains a NUL character",
            code=DomainCode.REDACTION_INPUT,
        )

    counts: Counter[RedactionCategory] = Counter()
    redacted = _replace_private_urls(text, counts)
    for pattern in _TEXT_PATTERNS:
        redacted, replacements = pattern.regex.subn(pattern.replacement, redacted)
        counts[pattern.category] += replacements
        if sum(counts.values()) > limits.max_redactions:
            raise LimitExceededError(
                "redaction replacement count exceeds the configured limit",
                context={"limit": limits.max_redactions},
            )
    redacted = _replace_high_entropy(redacted, counts)
    redacted = _replace_ip_candidates(redacted, counts)
    if sum(counts.values()) > limits.max_redactions:
        raise LimitExceededError(
            "redaction replacement count exceeds the configured limit",
            context={"limit": limits.max_redactions},
        )
    if verify_residual:
        assert_no_residual_sensitive_data(redacted)
    return redacted, counts


def residual_categories(text: str) -> tuple[RedactionCategory, ...]:
    """Return known sensitive categories still present after redaction."""

    residual: set[RedactionCategory] = set()
    if _PRIVATE_KEY_MARKER_RE.search(text):
        residual.add(RedactionCategory.PRIVATE_KEY)
    for pattern in _TEXT_PATTERNS:
        if pattern.regex.search(text):
            residual.add(pattern.category)
    for match in _PRIVATE_URL_RE.finditer(text):
        if _private_url_match(match):
            residual.add(RedactionCategory.PRIVATE_URL)
            break
    for match in _HIGH_ENTROPY_RE.finditer(text):
        if _looks_high_entropy(match.group(0)) and not _is_safe_relative_file_match(
            text, match
        ):
            residual.add(RedactionCategory.SECRET)
            break
    for regex in (_IPV4_CANDIDATE_RE, _IPV6_CANDIDATE_RE):
        for match in regex.finditer(text):
            try:
                ipaddress.ip_address(match.group(0).split("%", 1)[0])
            except ValueError:
                continue
            residual.add(RedactionCategory.IP_ADDRESS)
            break
    return tuple(category for category in RedactionCategory if category in residual)


def assert_no_residual_sensitive_data(text: str) -> None:
    """Fail closed when a known sensitive pattern remains in candidate output."""

    residual = residual_categories(text)
    if residual:
        raise RedactionError(
            "sensitive data remains after redaction",
            code=DomainCode.REDACTION_RESIDUAL,
            context={"categories": ",".join(category.value for category in residual)},
        )


def _counts(counter: Counter[RedactionCategory]) -> RedactionCounts:
    return RedactionCounts({category: counter[category] for category in RedactionCategory})


def _protect_allowed_literals(
    text: str, allowed_literals: Sequence[str]
) -> tuple[str, tuple[tuple[str, str], ...]]:
    protected = text
    replacements: list[tuple[str, str]] = []
    unique = sorted({literal for literal in allowed_literals if literal}, key=len, reverse=True)
    for index, literal in enumerate(unique):
        if any(ord(character) < 32 for character in literal):
            raise RedactionError(
                "allowed output literal contains a control character",
                code=DomainCode.REDACTION_INPUT,
            )
        marker = f"[SC_ALLOWED_LITERAL_{index}]"
        if marker in protected:
            raise RedactionError(
                "allowed output marker collides with content",
                code=DomainCode.REDACTION_INPUT,
            )
        protected = protected.replace(literal, marker)
        replacements.append((marker, literal))
    return protected, tuple(replacements)


def redact_output(
    text: str,
    *,
    allowed_literals: Sequence[str] = (),
    limits: Limits = DEFAULT_LIMITS,
) -> RedactionResult[str]:
    """Redact rendered output while preserving explicitly trusted literals.

    Trusted literals are intended for values produced by this process, such as the
    verified handoff path and its timestamps. They are protected before scanning;
    arbitrary user or recovered text must never be passed through this exemption.
    """

    protected, replacements = _protect_allowed_literals(text, allowed_literals)
    value, counter = _apply_text_patterns(
        protected, limits=limits, verify_residual=True
    )
    for marker, literal in replacements:
        value = value.replace(marker, literal)
    return RedactionResult(value=value, counts=_counts(counter))


def redact_structured(
    value: Any,
    *,
    limits: Limits = DEFAULT_LIMITS,
) -> RedactionResult[Any]:
    """Redact a bounded JSON-like structure using keys and scalar patterns.

    Mappings must have string keys.  Lists and tuples are preserved.  Arbitrary
    objects, byte strings, sets, and cycles are rejected rather than stringified,
    because implicit stringification can execute code or expose unreviewed data.
    """

    counter: Counter[RedactionCategory] = Counter()
    active: set[int] = set()
    item_count = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal item_count
        if depth > limits.max_structure_depth:
            raise LimitExceededError(
                "structured redaction exceeds the depth limit",
                context={"limit": limits.max_structure_depth},
            )
        item_count += 1
        if item_count > limits.max_structure_items:
            raise LimitExceededError(
                "structured redaction exceeds the item limit",
                context={"limit": limits.max_structure_items},
            )

        if item is None or isinstance(item, (bool, int, float)):
            return item
        if isinstance(item, str):
            redacted, additions = _apply_text_patterns(
                item, limits=limits, verify_residual=True
            )
            counter.update(additions)
            if sum(counter.values()) > limits.max_redactions:
                raise LimitExceededError(
                    "redaction replacement count exceeds the configured limit",
                    context={"limit": limits.max_redactions},
                )
            return redacted
        if isinstance(item, (bytes, bytearray, memoryview)):
            raise RedactionError(
                "binary values are not accepted for structured redaction",
                code=DomainCode.REDACTION_INPUT,
            )

        identity = id(item)
        if identity in active:
            raise RedactionError(
                "cyclic structures are not accepted for redaction",
                code=DomainCode.REDACTION_INPUT,
            )

        if isinstance(item, Mapping):
            active.add(identity)
            try:
                result: dict[str, Any] = {}
                for key, nested in item.items():
                    if not isinstance(key, str):
                        raise RedactionError(
                            "structured mappings must use string keys",
                            code=DomainCode.REDACTION_INPUT,
                        )
                    redacted_key, key_additions = _apply_text_patterns(
                        key, limits=limits, verify_residual=True
                    )
                    counter.update(key_additions)
                    if redacted_key in result:
                        raise RedactionError(
                            "redacted mapping keys are not unique",
                            code=DomainCode.REDACTION_INPUT,
                        )
                    category = _key_category(key)
                    if category is not None:
                        result[redacted_key] = _placeholder(category)
                        counter[category] += 1
                    else:
                        result[redacted_key] = visit(nested, depth + 1)
                return result
            finally:
                active.remove(identity)

        if isinstance(item, Sequence):
            active.add(identity)
            try:
                redacted_items = [visit(nested, depth + 1) for nested in item]
                return tuple(redacted_items) if isinstance(item, tuple) else redacted_items
            finally:
                active.remove(identity)

        raise RedactionError(
            "structured redaction accepts JSON-like values only",
            code=DomainCode.REDACTION_INPUT,
        )

    redacted_value = visit(value, 0)
    if sum(counter.values()) > limits.max_redactions:
        raise LimitExceededError(
            "redaction replacement count exceeds the configured limit",
            context={"limit": limits.max_redactions},
        )
    return RedactionResult(redacted_value, _counts(counter))


def redact_for_output(
    value: Any,
    *,
    serializer: Callable[[Any], str] | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> RedactionResult[str]:
    """Run structured redaction, render, then run output redaction.

    This is the preferred report boundary.  The final stage catches sensitive
    values introduced by formatting or by adjacency between individually safe
    structured fields.  Counts from both stages are added by category.
    """

    structured = redact_structured(value, limits=limits)
    if serializer is None:
        try:
            rendered = json.dumps(
                structured.value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise RedactionError(
                "redacted structure could not be serialized",
                code=DomainCode.REDACTION_INPUT,
            ) from error
    else:
        rendered = serializer(structured.value)
        if not isinstance(rendered, str):
            raise RedactionError(
                "output serializer must return text",
                code=DomainCode.REDACTION_INPUT,
            )

    output = redact_output(rendered, limits=limits)
    return RedactionResult(output.value, structured.counts.merged(output.counts))
