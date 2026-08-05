---
id:          TASK-118
title:       Refresh ARCHITECTURE.md and resolve protocol/doc version drift
status:      done
assignee:    ARCH.00
created_by:  ARCH.00
created:     2026-08-04
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [docs]
---

Surfaced by a 2026-08-04 project-state review, which found three concrete
documentation-drift issues:

1. **ARCHITECTURE.md is stale.** Its `Last updated` header reads
   2026-07-14 — roughly 19 closed tasks behind current HEAD. Concretely,
   the Phase 4 (Sharing) entry still reads "design complete, implementation
   not started," even though TASK-094 through TASK-097 plus TASK-106 and
   TASK-109 through TASK-113 have fully implemented, hardened, and closed
   both server-side sharing and shared-folder client sync. The document's
   own text already carries a prior audit note warning it was once caught
   fabricating a completion claim — treat every "complete"/"not started"
   marker in it as unverified until this refresh confirms it against actual
   TODO/ status and code.
2. **`docs/PROTOCOL.md`'s version number is inconsistent in three places**:
   the document's header states "Current version: 10"; `src/core/
   vw_proto.h`'s `VW_PROTO_VERSION_CURRENT` is `6`; the same document's own
   §11 Version History table's latest row is `16`. The history table
   appears to track a spec-revision/edit counter rather than the wire
   protocol version (most entries there say "no protocol version bump
   required") — if that's the intent, say so explicitly in the document so
   the three numbers stop looking like a contradiction; if the header's
   "10" is simply stale, correct it to match `vw_proto.h`.
3. **`ARCHITECTURE.md` documents `vw_cache` as owning "selective-sync
   rules"** — no such logic exists anywhere in `src/client/vw_cache.{h,c}`
   (confirmed by the review's grep). Either this is aspirational
   placeholder text that should be removed/reworded to reflect what
   `vw_cache` actually does today, or it's a real feature that was silently
   dropped and deserves its own follow-up task if the user wants it
   pursued — don't quietly delete the claim without flagging which of the
   two it is.

## Acceptance criteria

- `ARCHITECTURE.md`'s phase-status table matches the actual TODO/ status
  for every phase/feature it claims is complete, in-progress, or not
  started — verify against `TODO/TASK-*.md`, not against memory of past
  conversations.
- `docs/PROTOCOL.md`'s version-number sections are internally consistent,
  or explicitly explain why the three numbers legitimately mean different
  things. Coordinate this specific point with PRT.04, who owns
  `docs/PROTOCOL.md` per `CLAUDE.md`'s persistent-documents table — this
  task's assignee (ARCH.00) should not unilaterally rewrite PRT.04's
  document without their sign-off on the protocol-version framing.
- The `vw_cache` selective-sync claim in `ARCHITECTURE.md` is either
  corrected to match reality, or explicitly flagged (with a new follow-up
  task filed) if the user wants selective sync actually built.
- `ARCHITECTURE.md`'s `Last updated` header reflects the date this task
  closes.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested.

ARCH.00 [2026-08-05]: Resolved.

**1. `ARCHITECTURE.md` phase-status audit** — checked all 125 `TODO/TASK-*.md`
status fields (every file, not a sample), not memory of past conversations:
- Phase 4 (Sharing): was still wrong even after the 2026-07-29 correction —
  the fabrication was fixed, but by now the real implementation (`TASK-094`–
  `TASK-097`, plus `TASK-106`/`TASK-109`/`TASK-111`–`TASK-113` for
  shared-folder sync) had finished and the row was never updated to say so.
  Marked **complete**.
- Found two entire phases with no table row: Vault/E2EE (`TASK-089` design,
  `TASK-098`–`TASK-101` implementation) and Packaging/deployment/e2e-tests
  (`TASK-062`–`TASK-069`) — both referenced only in this doc's own "Last
  updated" header prose as "Phase 9"/"Phase 10", never given rows in the
  actual Implementation Phases table. Added as Phase 9 and Phase 10,
  both **complete**.
- Phase 8 (Hardening) row updated to reflect its actual, much larger span
  (`TASK-054`–`TASK-117`, `TASK-119`, `TASK-121`–`TASK-125`) and that
  `TASK-120` is the one thing still open.
- While auditing, also found the Approved External Dependencies table and
  Repository Structure listing both still described mbedTLS/Argon2 as
  vendored submodules — stale since `TASK-119`/`TASK-125` removed both.
  Corrected.
- Confirmed the `vw_cache` "selective-sync rules" claim (acceptance
  criterion 3, see below) and fixed it.
- Rewrote the "Last updated" header (was a dense one-off blurb from
  2026-07-14 for Phase 10 alone) and appended a 2026-08-05 note to the
  existing 2026-07-29 audit callout — didn't delete that note, since it's
  useful history, but flagged that the document drifted again within ten
  days of its last audit, so a "corrected" note doesn't mean a claim stays
  accurate.

**2. `docs/PROTOCOL.md` version numbers** — the three numbers were each
real and each measuring something different, not a case of one being
simply stale: `VW_PROTO_VERSION_CURRENT` (6) is the actual wire-negotiated
handshake version, last bumped for Phase 7 cluster support; the §11 table
(now 18) is a document-revision counter that increments for every
recorded change regardless of whether it required a wire bump — confirmed
by checking git history (`VW_PROTO_VERSION_CURRENT`'s value has never
changed since it was introduced at 6) against how many §11 entries
explicitly say "no protocol version bump required" (most of them, since
6). The header's "Current version: 10" matched neither and was pure
error. Fixed by splitting into two clearly-labeled fields rather than
picking one — see `docs/PROTOCOL.md` header and §11 revision 18.
Coordinated per this task's own instruction: proposed as ARCH.00, then
reviewed and confirmed by PRT.04 (document owner) before finalizing —
see the PRT.04 note below. Also fixed the header's **Status** line while
there (same paragraph, same kind of staleness): it said sharing's
client/GUI support and vault were still pending; both finished.

**3. `vw_cache` selective-sync claim** — confirmed via direct grep of
`src/client/vw_cache.{h,c}`: no selective-sync logic (per-subfolder
include/exclude) exists, and no task in `TODO/` — open or closed — ever
scoped building it. This reads as aspirational text written into the
original architecture doc, not a feature that was implemented and later
dropped. Corrected the Module Map row to describe what `vw_cache` actually
does (per-file sync state + sync-folder root tracking), and added an
explicit flag in `ARCHITECTURE.md` rather than silently deleting the
claim. **Not** filing a follow-up task to build selective sync — whether
users want that is a product-scope decision for the project owner, not
something to infer from a stale doc line. Flagging to the user directly
in this session's response instead.

**4. `Last updated` header** — set to 2026-08-05 (today).

PRT.04 [2026-08-05]: Reviewed the `docs/PROTOCOL.md` header framing
proposed above. Confirmed accurate: `VW_PROTO_VERSION_CURRENT` has
genuinely stayed at 6 since Phase 7 (verified via `git log -p` on
`src/core/vw_proto.h` — the `#define` line has only ever been added once,
never modified), and every §11 entry from 7 onward does state "no protocol
version bump required" where applicable. The two-field split resolves the
ambiguity without requiring any renumbering of past entries. Sign off.

CQR.08 [2026-08-05]: Checked every phase-status claim in the revised
Implementation Phases table against its cited task IDs' actual `status:`
fields — all match. Dependency table / Repository Structure / module-map
corrections are consistent with the current `third_party/` directory
listing (confirmed no `mbedtls/`/`argon2/` directories remain) and with
`TASK-119`/`TASK-125`. The `vw_cache` flag is handled correctly — corrected
in the doc, not silently dropped, and rightly not escalated into a new
task without the product-owner call. No blocking findings. Sign off.

ARCH.00 [2026-08-05]: All `review_by` sign-offs recorded (CQR.08, plus
PRT.04's document-ownership sign-off per this task's own coordination
requirement), no unresolved blocking findings. Marking `done`.
