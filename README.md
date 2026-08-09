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
- Create input arrives over UTF-8 stdin; request content is never placed in argv, environment variables, or a temporary request file.
- Handoffs use a canonical 19-heading Markdown schema, ordered `Next Actions`, a completion trailer, and SHA-256 integrity check.
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
