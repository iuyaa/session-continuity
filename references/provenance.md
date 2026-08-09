# Pinned upstream provenance

The authoritative immutable pins are also encoded in `src/session_continuity/provenance.py`.

## Upstreams

1. `mattpocock/skills` — `skills/productivity/handoff`
   - Commit: `84fdeffd12f2ee307994d1eb6feb48173b6e0502`
   - URL: `https://github.com/mattpocock/skills/tree/84fdeffd12f2ee307994d1eb6feb48173b6e0502/skills/productivity/handoff`
   - Adapted idea: explicit lightweight handoff from the current conversation.
2. `softaworks/agent-toolkit` — `skills/session-handoff`
   - Commit: `3027f20f3181758385a1bb8c022d4041dfb4de84`
   - URL: `https://github.com/softaworks/agent-toolkit/tree/3027f20f3181758385a1bb8c022d4041dfb4de84/skills/session-handoff`
   - Adapted idea: structured handoff lifecycle and current-project reconciliation.
3. `hacktivist123/agent-session-resume`
   - Commit: `76b025634ddc99b3ee3428fb4464af1c467da291`
   - URL: `https://github.com/hacktivist123/agent-session-resume/tree/76b025634ddc99b3ee3428fb4464af1c467da291`
   - Adapted idea: session discovery, evidence reconstruction, and layered evaluation.

Later upstream changes are not incorporated implicitly. Runtime operation performs no network access and never rewrites provenance. `python -B scripts/skill_provenance.py` prints the pins and local source hashes as JSON for inspection.

This distribution deliberately adds explicit `create`, report-only `resume`, bounded multi-session `deep`, Python stdin/JSON orchestration, fail-closed redaction, and the no-implicit-actions boundary. No upstream hook, service, agent, plugin packaging, automatic trigger, or session-file mutation is carried into the runtime design.
