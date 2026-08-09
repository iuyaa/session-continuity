# Session Continuity Design

## Goals

- Create one explicit, durable handoff from confirmed current-session state.
- Restore a handoff as a read-only report.
- Reconstruct one or more related Claude Code/Codex sessions as a read-only report.
- Keep runtime state limited to completed project-root handoffs.
- Run on Python 3.11+ using the standard library.

## Non-goals

Implicit invocation, automatic continuation, hooks, background services, MCP, agent orchestration, plugin packaging, settings, watchers, databases, indexes, digests, derived session caches, and mutation of source transcripts are outside the design.

## Architecture

```text
explicit /session-continuity invocation
        |
        v
SKILL.md validates user intent and constructs bounded input
        |
        v
scripts/session_continuity.py -> src/session_continuity/cli.py
        |
        +-- create -> redact -> canonical handoff -> exclusive publish/readback
        +-- resume -> strict handoff read -> drift comparison -> report -> stop
        `-- deep   -> bounded session discovery/reconstruction -> report -> stop
```

The wrapper uses `__file__` only to locate `src/`. The operated project root is the canonical invocation CWD or a valid containing Git top-level.

## Components

- `cli.py`: exact argparse grammar, bounded strict-UTF-8 create stdin, stable JSON results and exits.
- `commands.py`: create/resume/deep composition; no implicit action execution.
- `contracts.py`: immutable errors, exits, and resource ceilings.
- `paths.py`: canonical roots, containment, Windows syntax, link/reparse/hardlink and descriptor identity checks.
- `project_facts.py`: fixed read-only Git facts and explicitly named artifact hashes only.
- `redaction.py`: structured redaction, rendered-output redaction, typed counts, residual fail-closed checks.
- `handoff.py`: canonical 19-heading schema, ordered actions, local/UTC time, trailer/hash, exclusive publication, read-only validation.
- `sessions.py`: Claude/Codex candidate discovery, bounded multi-session selection, snapshot streaming, evidence projection and gaps.
- `provenance.py`: pinned upstream ideas and local source hashes; no network or sidecar.

## Command invariants

### Create

Create never imports session history for context, never enumerates old handoffs, and probes only fixed Git state plus artifacts explicitly named by the current request. It writes at most one final handoff and never overwrites an existing file.

### Resume

Resume accepts one direct `.handoffs/*.md`, verifies the trailer/hash/schema/privacy/project facts, reports current drift and ordered Next Actions, and performs no write.

### Deep

Explicit path or ID normally selects one source. Topic selection may choose up to the configured bounded set of high-confidence sessions from the same project. Evidence retains source-session identity, Codex live UUIDs outrank archive duplicates, and structured linked files must stay within the selected session's artifact root. Recovery writes nothing.

## Handoff contract

A handoff contains exactly one H1 and eighteen ordered H2 sections. Metadata, Next Actions, and Privacy/Redactions are strict JSON blocks. Other list sections use canonical Markdown bullets. The body is NFC-normalized UTF-8 without BOM and LF-only. A final completion trailer stores the schema version and SHA-256 of the body bytes.

Next Actions form an ordered list and may have multiple targets and dependencies. They are evidence for future user decisions, not executable instructions.

The filename uses one system-local timezone-aware instant and numeric UTC offset. Metadata stores both the local ISO 8601 time and its UTC conversion. UTC is the fallback if the system offset is unavailable.

## Security boundaries

- Grammar and bounded stdin validation occur before create-side filesystem operations.
- Untrusted paths are component-checked and descriptor-verified; Windows device/ADS/traversal/reserved names and link-based escapes are rejected.
- Session files are opened read-only and parsing stops at the captured descriptor size; concurrent append beyond that boundary is ignored.
- Malformed, invalid-UTF-8, oversized, incomplete, or unsupported records become bounded Evidence Gaps rather than trusted evidence.
- Thinking, reasoning, signatures, and encrypted content are omitted.
- Structured and full-output redaction cover credentials, authorization values, private keys, URL userinfo, emails, IP addresses, and filesystem paths. Known residuals block release.
- Content hashes detect corruption, not authorship.
- Python's Windows stdlib checks reduce path races but do not claim kernel-level race freedom against another same-user writer.

## Verification layers

1. Direct unit tests for contracts, rendering, redaction, selection, and streaming.
2. Filesystem/subprocess tests for no-overwrite create, immutable resume, zero-write deep, and wrapper behavior from unrelated CWDs.
3. Static Skill scenarios for explicit invocation and report-only stop behavior.

All fixtures are synthetic and created under temporary directories. Real user transcripts are never copied into tests.
