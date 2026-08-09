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
        +-- resume -> strict read -> scoped drift -> full report + concise view -> stop
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

## Synthesis and runtime boundaries

The Skill performs semantic synthesis, while Python performs mechanical validation, redaction, publication, and read-only reconciliation. This separation keeps schema v1 stable and avoids guessing business meaning in the runtime.

- `SKILL.md` derives an omitted focus from the confirmed Goal, checks unfinished-thread coverage, distinguishes Verified from Reported State, filters Skill-self process noise, and formats conditional actions and Suggested Skills.
- Python accepts the resulting bounded payload without importing transcripts or discovering additional files.
- Canonical references use the existing Artifacts section. Exact project files become optional named anchors only when the current request identifies them explicitly.
- Resume derives a concise continuation view from the already validated full report. The view is never persisted and does not replace any canonical section.
- Verified State evidence links remain textual `[E-###]` prefixes in schema v1; Next Action references retain strict parser enforcement.

## Command invariants

### Create

Create never imports session history for context, never enumerates old handoffs, and probes only fixed Git state plus artifacts explicitly named by the current request. Named artifacts are optional best-effort drift anchors: only safe, existing regular files with publishable relative paths are retained, while invalid, missing, unsafe, oversized, or privacy-sensitive entries are counted and skipped. An optional artifact failure never blocks the primary handoff. Create writes at most one final handoff and never overwrites an existing file.

### Resume

Resume accepts one direct `.handoffs/*.md`, verifies the trailer/hash/schema/privacy/project facts, and performs no write. It preserves the complete parsed report and derives an in-memory continuation view with canonical references, conditional unfinished actions, Suggested Skills, and an explicit report-only stop.

Drift is scoped rather than universal. Git comparison covers repository identity plus aggregate status counts and excludes `.handoffs/**`, individual paths, remotes, diffs, and logs. Named-artifact comparison covers only explicit saved anchors. The report identifies unavailable probes and lists databases, running services, external references, textual artifacts without anchors, and unnamed file contents as unchecked. `RESTORED` therefore means that no difference was detected within the checked scope.

### Deep

Explicit path or ID normally selects one source. Topic selection may choose up to the configured bounded set of high-confidence sessions from the same project. Evidence retains source-session identity, Codex live UUIDs outrank archive duplicates, and structured linked files must stay within the selected session's artifact root. Recovery writes nothing.

## Handoff contract

A handoff contains exactly one H1 and eighteen ordered H2 sections. Metadata, Next Actions, and Privacy/Redactions are strict JSON blocks. Other list sections use canonical Markdown bullets. The body is NFC-normalized UTF-8 without BOM and LF-only. A final completion trailer stores schema version 1 and `sha256`, the SHA-256 of body bytes before the trailer. JSON command results preserve that legacy name, add the explicit alias `body_sha256`, and expose `file_sha256` for the complete Markdown bytes. The aliases are report data and do not change the stored schema.

Next Actions form an ordered list and may have multiple targets and dependencies. A target is bounded, non-empty report data: it may identify a path, `file:line` location, URL, symbol, issue, or subsystem. Targets are not interpreted as filesystem paths or URLs, and recovery never opens or executes them. Structured and output redaction still applies before publication. Action status is canonicalized to `pending`, `ready`, `blocked`, `in_progress`, `done`, or `parked`; common English and Chinese aliases are accepted as input. Next Actions are evidence for future user decisions, not executable instructions.

The filename uses one system-local timezone-aware instant and numeric UTC offset. Metadata stores both the local ISO 8601 time and its UTC conversion. UTC is the fallback if the system offset is unavailable.

## Security boundaries

- Grammar and bounded stdin validation occur before create-side filesystem operations.
- Untrusted paths are component-checked and descriptor-verified; Windows device/ADS/traversal/reserved names and link-based escapes are rejected.
- Session files are opened read-only and parsing stops at the captured descriptor size; concurrent append beyond that boundary is ignored.
- Malformed, invalid-UTF-8, oversized, incomplete, or unsupported records become bounded Evidence Gaps rather than trusted evidence.
- Thinking, reasoning, signatures, and encrypted content are omitted.
- Structured and full-output redaction cover credentials, authorization values, private keys, URL userinfo, emails, IP addresses, and filesystem paths. Known residuals block release. The generic high-entropy heuristic preserves only strict project-relative file spans with a terminal extension; credential-specific, URL, address, and absolute-path checks still apply first.
- Content hashes detect corruption, not authorship.
- Python's Windows stdlib checks reduce path races but do not claim kernel-level race freedom against another same-user writer.

## Verification layers

1. Direct unit tests for contracts, rendering, redaction, selection, and streaming.
2. Filesystem/subprocess tests for no-overwrite create, immutable resume, zero-write deep, and wrapper behavior from unrelated CWDs.
3. Static Skill scenarios for explicit invocation and report-only stop behavior.

All fixtures are synthetic and created under temporary directories. Real user transcripts are never copied into tests.
