# Claude Code Session Sources

Default source root: `~/.claude/projects`.

Main sessions are direct UUID-named JSONL files under one project bucket. Nested `subagents`, `tool-results`, `artifacts`, workflows, memory, backups, and repair directories are not main candidates. They are read only when a selected main session contains a recognized structured link and the linked path remains inside that session's `<session-id>/` artifact directory.

Session files may be large and actively appended. Recovery captures descriptor identity and size, streams only to that boundary, ignores later append data, bounds lines/events/output, and records malformed or incomplete data as Evidence Gaps.

Visible user/assistant messages, tool calls/results, status and artifact evidence may be retained. Thinking, reasoning, signatures, encrypted content and unsupported sensitive structures are omitted.
