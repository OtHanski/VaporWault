---
id:          TASK-204
title:       "Re-audit and correct ARCHITECTURE.md drift"
status:      done
assignee:    ARCH.00
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [docs]
---

`ARCHITECTURE.md` has drifted from the actual repo state again, the same
class of problem its own 2026-07-29 and 2026-08-05 audit notes already
caught and warned would keep happening. A quick read against current
`TODO/done/` and recent commits (`a5a54fd`, `fbc68e3`) found, at minimum:

- The Implementation Phases table's Phase 11 (web gateway) row still
  reads "design published, implementation not started," but
  `TASK-128`-`144` are all `done` in `TODO/done/` and the gateway/
  frontend shipped in commit `a5a54fd`.
- The Phase 12 (multi-account) row still reads "design published,
  implementation not started," but `TASK-161`-`168` are all `done` and
  multi-account support shipped in the same commit.
- The document's own "Last updated" header predates both of the above by
  weeks, so it isn't just these two rows — treat the whole document as
  due for a full pass, not a two-line fix.
- `TASK-169`-`181` (replica hot-standby, client fallback, chunk-refcount
  fixes, commit `fbc68e3`) landed after the header date too and should
  have their own phase-table row or be folded into an existing one,
  consistent with how `TASK-169`'s own Decision Log entries already
  document the individual decisions (this task is about the phase-status
  table and header, not re-deriving decisions the Decision Log already
  has correctly).

## Work

- Re-audit every phase-status claim in the Implementation Phases table
  against every `TODO/done/`+`TODO/todo/` task file's actual `status:`
  field (all of them, not a sample — repeat `TASK-118`'s method, since
  sampling is exactly how this drifted unnoticed before).
- Add/update phase rows for anything shipped since the last audit
  (multi-account, web gateway, replica hot-standby/fallback) and for the
  new design tasks filed this session (`TASK-182`, `185`, `192`, `196` and
  their breakdowns), once those actually reach `done`.
- Update the "Last updated" header to the date of this pass, and note in
  it (as the existing audit notes already do) which prior claims were
  found wrong and why — keep that self-correcting-log style, it's what
  caught the last two rounds of drift.
- Spot-check the Approved External Dependencies table and Repository
  Structure listing again — the 2026-08-05 note fixed a stale mbedTLS/
  Argon2-as-submodule claim there once already.

## Acceptance criteria

- Every "complete"/"done" claim in the Implementation Phases table is
  verified against an actual `TODO/` task file's status, not against
  memory of past conversations.
- The audit method and findings are recorded as a dated note in the
  document itself, same style as the existing 2026-07-29/2026-08-05
  notes, so the next drift (there will be a next one) has a trail to
  follow.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-25]: Filed after a feature-gap review surfaced the Phase
11/12 status drift described above.

ARCH.00 [2026-08-26]: Re-audited and corrected. Checked all 218 `TODO/`
task files' `status:` fields (not a sample) against the Implementation
Phases table.

- Corrected Phase 11 (Web gateway) and Phase 12 (Multi-account) to
  **complete** — both were still "design published, implementation not
  started" despite every task in each wave (`TASK-128`-`144`,
  `TASK-161`-`168`) being `done`.
- Added Phases 13-19 for entire feature waves that had shipped with no
  table row at all: installer packages (`TASK-145`-`154`, one item —
  `TASK-152` — still open, called out honestly rather than marked
  complete), replica hot-standby + client fallback (`TASK-169`-`181`),
  client version history (`TASK-182`-`184`, plus the still-open shared-file
  gap `TASK-214`), public link password protection (`TASK-185`-`191`),
  selective sync (`TASK-192`-`195`), filename search (`TASK-196`-`202`),
  and version-string embedding (`TASK-203`).
- Added Phase 20 for the opt-in email alert system (`TASK-205`-`213`),
  currently in progress — documented now rather than only after it ships,
  unlike every phase above.
- Extended Phase 8's (Hardening) description to name the bug-fix tasks
  found since the last audit while implementing/verifying later features
  (`TASK-155`-`157`, `159`, `217`, `218`) rather than leaving them
  undocumented.
- Repository Structure listing: added `cmake/`, `packaging/`, the new root
  `VERSION` file, and three real `docs/` files that existed but were never
  listed (`DEPLOYMENT.md`, `TUTORIAL.md`, `CLIENT_GETTING_STARTED.md`) —
  confirmed all of these actually exist on disk before adding them, not
  assumed from task titles.
- Spot-checked the Approved External Dependencies and Architectural
  Decisions tables against the current source tree — both found current,
  no changes needed.
- Full dated audit note added to `ARCHITECTURE.md` itself (2026-08-26
  follow-up, same style as the 2026-07-29/2026-08-05 notes), including an
  honest observation that entire shipped phases going undocumented (not
  just a stale status word) suggests the audit-after-the-fact process
  itself is the weak point — recorded as a suggestion for ARCH.00 to
  consider (add a phase row when closing each design task), not
  unilaterally adopted as a new rule here.
- Did not touch `CLAUDE.md` even though its Persistent Documents table is
  missing `docs/DEPLOYMENT.md`/`TUTORIAL.md`/`CLIENT_GETTING_STARTED.md`
  too — out of this task's stated scope (`ARCHITECTURE.md` specifically);
  noting it here rather than silently fixing or silently ignoring it.

Moving to `review`.

CQR.08 [2026-08-26]: Reviewed for accuracy and consistency.

- Spot-checked a sample of the new phase rows' task-ID ranges (13, 15, 20)
  directly against `TODO/done/`/`TODO/todo/` file presence rather than
  trusting the note's own claim — ranges match.
- Confirmed `cmake/`, `packaging/`, and `VERSION` actually exist at the
  paths now listed in Repository Structure (`ls` at repo root) rather than
  taking the note's word for it.
- The new phase rows follow the existing rows' own citation style
  (task-ID ranges, dated corrections, honest "one item still open" callouts
  for Phase 13/15) rather than introducing a different format.
- The self-critical process observation at the end of the new audit note
  (phases going undocumented, not just stale status words, points at the
  audit-after-the-fact process itself) is framed as a suggestion for
  ARCH.00, not a unilateral rule change — appropriate scope for a docs
  task.
- Correctly left `CLAUDE.md` untouched and said so explicitly rather than
  silently expanding scope or silently leaving a known gap unmentioned.
- No blocking findings. Approved.
