---
id:          TASK-118
title:       Refresh ARCHITECTURE.md and resolve protocol/doc version drift
status:      todo
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
