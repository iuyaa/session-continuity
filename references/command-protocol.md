# Command Protocol

The root Skill invokes `scripts/session_continuity.py` with one explicit subcommand. `create` receives one strict UTF-8 JSON object over stdin; `resume` and `deep` receive their selector through argv and do not consume recovered commands.

## Interpreter selection

Use an interpreter-selection probe before the business command. On Windows, prefer `python -B`; if it is missing or below 3.11, try `py -3.11 -B`. On POSIX, prefer `python3.11 -B`, then another verified Python 3.11+ executable. Once the business script starts, propagate its result and never retry it with another interpreter.

Every real invocation uses `-B`. The Skill must preserve the invocation working directory and resolve the script relative to its own root.

## Create

```text
python -B <skill-root>/scripts/session_continuity.py create [focus]
```

Stdin schema:

```json
{
  "handoff": {
    "goal": "Confirmed goal",
    "verified_state": ["[E-001] Confirmed fact"],
    "reported_state": [],
    "in_progress": [],
    "deferred_parked": [],
    "not_done": [],
    "decisions_constraints": [],
    "files_changed": [],
    "commands_run": [],
    "verification": [],
    "artifacts": [],
    "environment": [],
    "evidence_provenance": ["E-001: Current tool result"],
    "exact_stopping_point": "Where work stopped",
    "next_actions": [
      {
        "order": 1,
        "status": "pending",
        "action": "Review the recovered state",
        "targets": ["https://example.com/issues/123"],
        "depends_on": [],
        "acceptance": "User confirms the next implementation step",
        "evidence_refs": ["E-001"]
      }
    ],
    "suggested_skills": ["review-changes — review the next implementation delta"]
  },
  "named_artifacts": {}
}
```

`named_artifacts` is optional and best-effort. Normally send an empty object. When present, values identify exact existing files, not directories, globs, URLs, or `file:line` references. Entries that cannot be safely hashed or published are counted and skipped; they do not fail `create`.

The successful JSON result contains `ok`, `action`, absolute `path`, `sha256`, `body_sha256`, `file_sha256`, `created_local`, `created_utc`, `timezone_offset`, `redactions`, `size`, and a `named_artifacts` summary with `requested`, `anchored`, and `skipped` counts. `sha256` and `body_sha256` identify the body bytes before the completion trailer; `file_sha256` identifies the complete published Markdown bytes. A target is a non-empty, inert locator string; the runtime redacts it but never interprets, opens, or executes it. Next Action status is stored as one of `pending`, `ready`, `blocked`, `in_progress`, `done`, or `parked`; common English and Chinese input aliases are normalized before publication. Readers that predate `in_progress` support need an update before consuming a handoff that uses that status.

## Resume

```text
python -B <skill-root>/scripts/session_continuity.py resume <handoff-path>
```

The result preserves the complete report-only parsed handoff and adds current read-only project facts, `drift`, `drift_scope`, and `continuation`. The continuation object is an in-memory projection containing identity and body/file hashes, Goal, exact stopping point, canonical references, drift guidance, up to five unfinished actions in stored order, Suggested Skills, and `execution_authorized: false`. Every action, including omitted, blocked, parked, and done entries, remains present in the full `next_actions` array.

`drift_scope` distinguishes checked repository, checked non-repository, and unavailable Git probes. Git comparison covers repository identity and aggregate status counts and excludes `.handoffs/**`, paths, remotes, diffs, and logs. Named-artifact coverage reports saved, checked, matched, changed, and unavailable counts. Database contents, running services, external references, textual artifacts without anchors, and unnamed file contents are reported as unchecked. `RESTORED` retains its compatible meaning: no difference was detected within the checked scope. No action is executed.

## Deep

```text
python -B <skill-root>/scripts/session_continuity.py deep <session-path|id|topic>
```

An explicit path or UUID normally returns one session. A topic may return a bounded, same-project multi-session report. The result exposes source-tagged events, linked sources, Evidence Gaps, limits/truncation, and statistics. It performs no write and executes no recovered command.

## Results and exits

Every success writes one sanitized JSON object and exits `0`. Expected failures also write one sanitized object:

```json
{"ok":false,"error":{"code":"stable_code","exit_code":3,"message":"compact message"}}
```

Stable exits are `0` success, `2` usage, `3` validation/selection/redaction, `4` path/snapshot/integrity, and `5` OS I/O/publication. Raw secret values and untrusted absolute paths are never included in error output.
