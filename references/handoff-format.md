# Handoff Format

A valid handoff contains these headings exactly once and in this order:

```text
# Session Handoff
## Metadata
## Goal
## Verified State
## Reported State
## In Progress
## Deferred/Parked
## Not Done
## Decisions/Constraints
## Files Changed
## Commands Run
## Verification
## Artifacts
## Environment
## Evidence/Provenance
## Exact Stopping Point
## Next Actions
## Suggested Skills
## Privacy/Redactions
```

Metadata, Next Actions, and Privacy/Redactions contain one strict fenced JSON block. Empty list sections render as `- None.`. Evidence identifiers use `E-###`; Verified State items may carry textual `[E-###]` prefixes, while Next Actions may reference only identifiers defined in Evidence/Provenance. Each action target is a non-empty, inert locator string; it is redacted before publication and is never opened or executed. Canonical action statuses are `pending`, `ready`, `blocked`, `in_progress`, `done`, and `parked`. Readers released before `in_progress` support must be updated before consuming a handoff that uses that status; current readers remain compatible with earlier schema-v1 handoffs. Suggested Skills remain strings and use `skill-name — reason` when a reason is available. Metadata retains only named artifact anchors that were safely hashed and whose relative paths survived privacy scanning; skipped optional anchors are reported in the create result rather than embedded in the handoff.

The canonical body uses NFC-normalized UTF-8 without BOM and LF line endings. The final line is a completion trailer containing schema version 1 and lowercase `sha256`, the SHA-256 of all body bytes before the trailer. Nothing follows except the final LF. Create and resume JSON results may add the compatible aliases `body_sha256` and `file_sha256`; continuation and drift-scope objects are derived in memory and are never stored in the schema-v1 Markdown file.
