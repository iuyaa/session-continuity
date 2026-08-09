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

Metadata, Next Actions, and Privacy/Redactions contain one strict fenced JSON block. Empty list sections render as `- None.`. Evidence identifiers use `E-###`. Next Actions are ordered report data and may reference only evidence identifiers defined in Evidence/Provenance.

The canonical body uses NFC-normalized UTF-8 without BOM and LF line endings. The final line is a completion trailer containing schema version 1 and the lowercase SHA-256 of all body bytes before the trailer. Nothing follows except the final LF.
