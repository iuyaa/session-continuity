# Session Continuity

`session-continuity` is an explicitly invoked Claude Code Skill for preserving the current task or reconstructing prior Claude Code and Codex context as a report.

```text
/session-continuity create [focus]
/session-continuity resume <handoff-path>
/session-continuity deep <session-path|id|topic>
```

- `create` publishes one verified project-root `.handoffs/*.md` using the system-local timezone and UTC metadata.
- `resume` validates one named handoff, reconciles current project drift, reports the recovered context, and stops.
- `deep` reconstructs a bounded set of related sessions, reports source-tagged evidence and gaps, and stops.

Only `create` writes. `resume`, `deep`, and every recovered Next Action are report-only.

## One durable file, two views

Session Continuity separates durable storage from continuation presentation. It stores one complete handoff and derives the concise view in memory when you resume it.

- The canonical handoff retains all 19 sections, evidence, commands, files, ordered actions, privacy counts, and body-integrity trailer.
- The full resume report preserves every parsed field and action status for machine consumers.
- The continuation view presents the Goal, stopping point, scoped drift, canonical references, up to five unfinished conditional actions, Suggested Skills, and an explicit stop condition.
- No second summary file, digest, index, or cache is written.
- `RESTORED` means no difference was detected within the checked Git and explicit artifact-anchor scope. Databases, services, external references, and unanchored content remain outside that scope.

Create and resume results retain `sha256` as the canonical body hash, expose the clearer alias `body_sha256`, and also return `file_sha256` for all bytes including the completion trailer.

## Requirements

- Claude Code with root Skill-directory support.
- Python 3.11 or newer.
- Standard-library runtime; Git is queried read-only when available.

## Install

Install the complete repository as a Skill directory named `session-continuity`:

```text
~/.claude/skills/session-continuity/
```

On Windows, copy or link the complete repository to:

```text
%USERPROFILE%\.claude\skills\session-continuity\
```

Restart Claude Code and invoke `/session-continuity` explicitly. The repository root is the Skill root; there is no nested `.claude` directory.

## Design summary

- The script wrapper locates `src/` from its own path, while the operated project root comes from the invocation working directory or its valid Git top-level.
- Optional named artifact hashes are best-effort drift anchors. Invalid or sensitive entries are counted and skipped without blocking handoff creation.
- Create input arrives over UTF-8 stdin; request content is never placed in argv, environment variables, or a temporary request file.
- Handoffs use a canonical 19-heading Markdown schema, ordered `Next Actions` with inert, redacted locator targets, a completion trailer, and SHA-256 integrity check.
- Publication uses exclusive no-overwrite creation and close/reopen readback verification.
- Claude/Codex JSONL recovery is descriptor-bound, bounded, and tolerant of evidence gaps and concurrent append beyond the captured snapshot.
- Structured and rendered-output redaction run before any file/stdout result is released.

## Documentation

- [Architecture and threat model](DESIGN.md)
- [Handoff format](references/handoff-format.md)
- [Command protocol](references/command-protocol.md)
- [Claude Code sources](references/claude-code.md)
- [Codex sources](references/codex.md)
- [Cross-platform behavior](references/cross-platform.md)
- [Evidence and provenance](references/evidence-and-provenance.md)
