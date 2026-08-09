# Codex Session Sources

Default live root: `~/.codex/sessions`, organized as `YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl`. Default archive root: `~/.codex/archived_sessions`.

Discovery accepts only rollout JSONL names with a valid UUID. If live and archive contain the same UUID, the live source wins. Exact IDs select one source; topic recovery may select a bounded same-project set.

Records are streamed read-only to a captured descriptor boundary. Visible messages, tool calls/results, task statuses and current-project evidence may be retained. Encrypted reasoning, analysis, signatures and unsupported private structures are omitted. Codex source files and archives are never edited or cached.
