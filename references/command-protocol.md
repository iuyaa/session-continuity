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
    "verified_state": ["Confirmed fact"],
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
        "targets": [],
        "depends_on": [],
        "acceptance": "User confirms the next implementation step",
        "evidence_refs": ["E-001"]
      }
    ],
    "suggested_skills": []
  },
  "named_artifacts": {}
}
```

The successful JSON result contains `ok`, `action`, absolute `path`, `sha256`, `created_local`, `created_utc`, `timezone_offset`, `redactions`, and `size`.

## Resume

```text
python -B <skill-root>/scripts/session_continuity.py resume <handoff-path>
```

The result contains a report-only parsed handoff, current read-only project facts, drift entries, and ordered Next Actions. No action is executed.

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
