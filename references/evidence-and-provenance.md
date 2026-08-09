# Evidence and Provenance

## Evidence classes

- **Verified**: observed current-project facts or matched tool-call/tool-result records.
- **Reported**: user/assistant narrative retained as a claim.
- **Unverified**: conflicting, missing, malformed or unsupported records.
- **Evidence Gap**: a bounded explanation for data that was skipped or unavailable.

Current read-only project facts outrank historical narrative. Every deep event retains its source session. Structured linked files retain their source artifact and must stay inside the selected session artifact root.

## Upstream pins

- Matt Pocock handoff: `84fdeffd12f2ee307994d1eb6feb48173b6e0502`.
- Softaworks session-handoff: `3027f20f3181758385a1bb8c022d4041dfb4de84`.
- Hacktivist123 agent-session-resume: `76b025634ddc99b3ee3428fb4464af1c467da291`.

`python -B scripts/skill_provenance.py` prints pinned sources and local source hashes to stdout. It performs no network access and writes no sidecar. See `references/provenance.md` for full immutable URLs.
