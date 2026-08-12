---
id:          TASK-088
title:       Design and implement file/folder sharing between users
status:      done
assignee:    ARCH.00
created_by:  ARCH.00
created:     2026-07-24
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, client, gui, protocol, security-sensitive]
---

Confirmed absent, not just unpolished: storage is strictly per-`owner_id`
(`src/server/vw_store_files.c`) with no ACL/grant concept anywhere in
`src/server` or `src/core`. There is no way for one user to share a file or
folder with another user, and no public/external link mechanism. For a
"cloud file hosting" product this is likely the single most-expected
feature after basic sync/versioning (both of which already exist — version
history is fully implemented via `VERSION_LIST`/`VERSION_RESTORE`).

This is a cross-cutting feature (new wire protocol messages, a server-side
permission/grant model, client sync-engine awareness of shared folders, GUI
views) — too large to hand directly to one agent. Per the coordination
workflow in `CLAUDE.md`, this task is ARCH.00's to decompose:

1. Design the API contract: what can be shared (single file vs. whole
   folder), grant model (per-user vs. link-based, read vs. read-write),
   how shared items appear in the recipient's own namespace/sync tree, and
   how quota accounting works for shared (non-owned) storage. Record
   decisions in `ARCHITECTURE.md`.
2. PRT.04 publishes the relevant `docs/PROTOCOL.md` section (new message
   types for share/unshare/list-shares, and any changes to existing
   file-listing messages to surface shared items) before SRV.01/CLI.02 pick
   up implementation tasks (routing rule 3).
3. Spawn SRV.01 (storage/permission model, server-side grant enforcement —
   this is the security-critical part: must prevent path traversal into
   another user's storage and correctly gate reads vs. writes), CLI.02
   (sync engine handling of shared folders), and GUI.03 (share/unshare UI,
   permission indicators) subtasks once the contract is settled.

## Acceptance criteria

- `ARCHITECTURE.md` records the sharing model decision (scope, grant types,
  quota treatment) before implementation tasks are created.
- `docs/PROTOCOL.md` has a versioned section for the new wire messages.
- SEC.07 signs off specifically on cross-user access control (this is
  exactly the class of bug — cross-user data exposure — SEC.07's domain
  description calls out explicitly: "Storage layer: path traversal,
  cross-user access").
- Follow-up implementation tasks are filed with correct `depends_on` edges
  once the design is settled.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-24]: Filed as a design-first task per the standard feature
workflow (Step 1 in `CLAUDE.md`) rather than a single implementation task —
the scope genuinely spans protocol, server, client, and GUI, and the
permission model needs to be settled before any of those can start in
parallel without rework.

ARCH.00 [2026-07-29]: Before designing on top of it, discovered and fixed a
documentation-integrity problem: `ARCHITECTURE.md`'s Phase 4 row falsely
claimed sharing was "complete", citing TASK-034/035 (actually CI setup and
Dear ImGui vendoring) and referencing a `vw_users` module that was never
created. Confirmed via direct source inspection (zero permission/share/grant
code anywhere in `src/server`) and git history (`ARCHITECTURE.md` has never
been incrementally updated). Corrected the Module Map, on-disk layout, and
Phase 4 row, and added a broader audit-note disclaimer on the rest of the
document. Reported to the user before proceeding.

ARCH.00 [2026-07-29]: Design settled per the user's explicit requirements
("share both files and folders"; "both user-to-user sharing and public
read/edit links"; "files count against the owner's quota") and published:

- **Data model**: new `vw_share_record_t` (128 bytes, matching this
  codebase's fixed-size-record convention) — see `docs/PROTOCOL.md` §7.5 for
  the full field list. Both user-to-user grants and public links are rows in
  the same table (`share_type` discriminates), since both need the same
  owner/target/file_id/permission/revoked/expiry shape.
- **Wire protocol**: fully specified in `docs/PROTOCOL.md` §7.5 (message
  catalog: `SHARE_GRANT`/`_REVOKE`/`_LIST` completed with real payloads;
  `LINK_CREATE`/`_REVOKE`/`_LIST`/`LINK_ACCESS` added, repurposing the never-
  implemented `SUB_CREATE`/`SUB_DELETE` opcodes 0x0507–0x050A) and §7.10
  (security model). Protocol version bumped 6→7.
- **Public-link mechanism**: reuses the existing `INVITE_REDEEM` precedent —
  an unauthenticated pre-`AUTH_REQUEST` message (`LINK_ACCESS`) redeems a
  256-bit token and establishes a *scoped* session (`user_id=0`, bound to one
  `share_id`), so all existing file-op dispatch, quota, and oplog machinery
  is reused rather than building a parallel unauthenticated code path. This
  required confirming `vw_session_record_t` has enough reserved space
  (`_pad[70]`) to add `scope_file_id`/`scope_permission` fields without
  growing the struct — same "reuse reserved bytes" pattern as `TASK-090`'s
  `deleted_at`.
- **Permission-check rule**: extends the existing owner-only check in
  `vw_file_handlers.c` with two more checks (walk-up share grant, scoped-
  session match) in a fixed order, full text in §7.5. A user can only
  grant/link up to their own effective permission — prevents a READ grantee
  escalating a third party to EDIT.
- **Quota rule (explicit per requirement)**: storage always counts against
  the file's actual `owner_id`, never the acting session's `user_id` —
  applies uniformly whether the acting session is a different authenticated
  user via an EDIT grant, or an anonymous public-edit-link session. This is
  also what bounds abuse potential from a public edit link.
- **Live revocation property flagged for SEC.07**: a revoked share must
  invalidate an already-issued scoped session's access on its *next*
  request — checked live against the share record every time, not cached at
  `LINK_ACCESS` time. This is a correctness requirement, not just hardening,
  and is easy to get wrong by treating "session already validated" as
  sufficient.
- **Dropped from the old skeleton**: the `SUB_CREATE`/`SUB_DELETE`
  "subscription" concept — nothing in the settled requirements needs it, and
  it was never implemented, so no compatibility risk in repurposing its
  opcodes.

Follow-up implementation tasks filed with `depends_on: [TASK-088]`:
`TASK-094` (SRV.01 — server storage/permission/protocol implementation),
`TASK-095` (CLI.02 — client library + sync engine), `TASK-096` (GUI.03 —
share/link UI, depends on TASK-095 per the existing GUI.03 constraint),
`TASK-097` (QA.06 — integration tests, depends on TASK-094/095).

Moving status to `review` — this task's own scope was design-and-decompose
(Step 1 of the coordination workflow), which is now done; per the
`security-sensitive` tag both SEC.07 and CQR.08 must review the design
itself (not just future implementation code) before this closes, per the
acceptance criteria's explicit call for SEC.07 sign-off on the cross-user
access control model.

SEC.07 [2026-07-29]: Adversarial design review complete. This task cannot
move to `done` until the `blocking` items below are resolved in the design
(§7.5/§7.10) before `TASK-094` starts implementation.

**Blocking:**

1. **FILE_MOVE crosses the sharing boundary undefined.** Nothing in §7.5
   says FILE_MOVE must check permission on both the *source* and
   *destination* `parent_dir_id`, nor does it forbid moving a folder under
   its own descendant. Concrete scenario: Bob has an EDIT grant on Alice's
   folder A. Bob moves a file out of A into his own folder B. The file's
   `owner_id` stays Alice (quota still charges her), but its
   `parent_dir_id` chain no longer passes through A — Alice loses all
   visibility/access to her own file (it's now nested under Bob's private
   tree), while it silently continues consuming her quota forever. Separately,
   the permission walk-up algorithm assumes an acyclic `parent_dir_id` tree;
   nothing prevents FILE_MOVE from creating a cycle (moving a directory
   under its own descendant), which would hang or misevaluate every
   walk-up check for that subtree. `TASK-094` must specify: authorize both
   source and destination parents, and reject moves that would create a
   cycle.
2. **Anonymous/scoped sessions aren't barred from `SHARE_GRANT`/
   `LINK_CREATE`.** §7.5's "grant only up to your own effective permission"
   rule never states the granter must be an authenticated (non-scoped)
   session. Concrete scenario: someone possesses a leaked/forwarded EDIT
   public link. They redeem it (`LINK_ACCESS`, `user_id=0`, scoped session),
   then call `SHARE_GRANT` (naming themselves via a real username they
   control, or a third party) or `LINK_CREATE` to mint a brand-new,
   independent `share_id`. This new grant is a separate row from the
   original link's `share_id` — revoking the original leaked link does
   **nothing** to it. This defeats "live revocation" precisely in the
   scenario it exists to solve (a link leaking outside the app). The design
   must explicitly require `session.user_id != 0` (a real authenticated,
   non-scoped session) to call `SHARE_GRANT`/`LINK_CREATE`.
3. **No cap on file/version/share-record creation independent of byte
   quota.** Quota resolution bounds storage *bytes*, but nothing bounds the
   *count* of files/versions/oplog entries an anonymous public-edit-link
   session can create. Concrete scenario: an anonymous holder of a public
   edit link `FILE_COMMIT`s millions of zero- or near-zero-byte files —
   each consumes a `meta.dat`/`versions.dat` slot and an oplog entry
   (replicated to every cluster node), effectively unbounded, while barely
   touching the owner's byte quota. Unlike a malicious authenticated user
   (who can be suspended via admin), this is a genuinely new *unauthenticated*
   write-DoS surface introduced by the public-link feature and isn't
   addressed anywhere in §7.5/§7.10.

**Advisory:**

- Same-request TOCTOU: the design says permission must be re-derived "on
  every request," which closes cross-request caching gaps, but says nothing
  about locking discipline within one request (e.g., a concurrent
  `SHARE_REVOKE` racing an in-flight `FILE_COMMIT` on the same file). Worth
  a locking note in `TASK-094`, not blocking the design sign-off.
- `LINK_ACCESS` reuses `NODE_HELLO`'s IP rate-limiter, which is a
  fixed 256-entry in-memory ring buffer sized for a handful of trusted
  cluster nodes. For an internet-facing anonymous endpoint, an attacker
  with >256 rotating source IPs can evict earlier entries and bypass
  per-IP tracking. Not blocking — the 256-bit token space already makes
  brute force infeasible regardless of rate limiting — but the mismatch in
  intended scale is worth a dedicated table size for `LINK_ACCESS` at
  implementation time.

**Verified sound:** `vw_session_record_t._pad[70]` is real and easily
covers `scope_file_id`(u64)+`scope_permission`(u8) as claimed. The
owner-quota resolution and grant-escalation-prevention logic (for
authenticated, non-scoped grantors) is correctly specified. The permission
rule ordering (owner → grant walk-up → scoped-session → deny) is sound as
far as it goes — findings 1–3 above are gaps in what's *not yet* covered by
that rule, not flaws in the rule itself.

CQR.08 [2026-07-29]: Design review complete (consistency, completeness,
naming). This task cannot move to `done` until the `blocking` items below
are resolved.

**Blocking:**

1. **`permission` field collides with the existing, already-used
   `vw_perm_t` enum.** `vw_proto.h` already defines `VW_PERM_NONE/VIEW/EDIT/
   OWNER = 0/1/2/3`, and `FILE_LIST_RESP`/`FILE_STAT_RESP` already carry a
   per-entry `perm` byte (currently hardcoded `VW_PERM_OWNER` since no
   sharing exists yet). §7.5's new `permission` field instead defined
   `0=READ, 1=EDIT` — different name *and* different numeric encoding from
   `vw_perm_t.EDIT=2`. Neither `TASK-094` nor `TASK-096` (which needs the
   existing `perm` byte to show read-vs-edit in the file browser) had any
   instruction to reconcile these into one scheme.
2. **`permission_needed_for_this_op` is used in the permission-check rule
   but never defined anywhere.** Ambiguous cases in particular:
   `VERSION_RESTORE`, `FILE_MOVE` (source vs. destination folder — possibly
   different owners/grants), and file creation under a shared folder (whose
   `owner_id` does the new file get?). Without a table, SRV.01 (`TASK-094`)
   and QA.06 (`TASK-097`) would each have had to invent this independently
   and likely disagree.
3. **`blocks`/`depends_on` graph asymmetry**: `TASK-094.blocks` listed
   `TASK-096`, but `TASK-096.depends_on` only listed `TASK-095` (correctly,
   since GUI consumes the client library only — but that left `TASK-094`'s
   `blocks` entry overstated/orphaned). Same pattern between `TASK-096.blocks`
   → `TASK-097` and `TASK-097.depends_on`.
4. **`TASK-099`'s `depends_on` omitted `TASK-098`** despite its own
   acceptance criteria requiring a live round-trip against the real server
   (which needs `TASK-098`'s handlers) — the sharing side's equivalent task
   (`TASK-095`) got this right by depending on `TASK-094` for the same
   reason; the E2EE side didn't apply the same pattern.

**Advisory:**

- `LINK_ACCESS_ACK`'s scoped session gives no way for the redeeming client
  to discover what `scope_file_id`/children it now has — worth resolving
  before `TASK-094`/`TASK-095` implementation diverges on it.
- `TASK-095`'s note ("client-side work can start in parallel") reads oddly
  next to its own hard `depends_on: [TASK-088, TASK-094]` — a one-line
  clarification that encode/decode isn't blocked, only wire-testing is,
  would help.

**Verified sound:** message catalog ↔ payload descriptions ↔ version-history
entries are internally consistent (opcodes, field order); `_pad[70]`/
`_reserved[32]` capacity claims check out against `vw_store.h`; the ordered
permission-check rule's "any of" phrasing correctly resolves file-vs-
ancestor-grant composition.

ARCH.00 [2026-07-29]: All SEC.07 and CQR.08 blocking findings resolved in
`docs/PROTOCOL.md` §7.5 (version bumped in place, same design-stage
revision — nothing has implemented v7 yet so no compatibility break):

- CQR.08 #1/#2: `permission` field now reuses `vw_perm_t` directly
  (`VW_PERM_VIEW`/`VW_PERM_EDIT`); added a full required-permission-per-
  operation table covering every ambiguous case raised, including the
  file-creation-under-shared-folder ownership question (new file's
  `owner_id` = the folder's `owner_id`).
- CQR.08 #3/#4: fixed the `blocks`/`depends_on` graph (`TASK-094.blocks`
  and `TASK-096.blocks` overstated entries removed; `TASK-099.depends_on`
  now includes `TASK-098`).
- CQR.08 advisory (scoped-session navigation): specified — `FILE_LIST`
  with `parent_dir_id==0` from a scoped session returns the scoped item or
  its children, never the real root.
- SEC.07 #1 (FILE_MOVE): added the ownership rule
  (`destination_parent.owner_id == file.owner_id`) closing the
  quota/visibility-hijack path, plus a general directory-move cycle check.
- SEC.07 #2 (grant/link escalation via scoped session): `SHARE_GRANT`/
  `SHARE_REVOKE`/`LINK_CREATE`/`LINK_REVOKE` now explicitly require
  `session.user_id != 0`, rejecting any scoped session outright.
- SEC.07 #3 (unbounded anonymous writes): added an explicit requirement for
  a per-scoped-session write-count rate limit, independent of byte quota.
- SEC.07 advisory (LINK_ACCESS rate-limit table sizing): left as an
  implementation-time decision for `TASK-094` — noted there, not blocking.

All follow-up subtasks (`TASK-094`–`TASK-097`) updated to reference these
fixes explicitly, not just rely on them being present in the linked
protocol section. Dispatching an independent re-verification pass before
closing this task, matching the practice established for `TASK-085` earlier
in this project (self-attestation of a fix is not sufficient sign-off).

ARCH.00 [2026-07-29]: Independent re-verification pass complete (fresh
agent, no context from the fix itself). All 3 SEC.07 blocking findings and
all 4 CQR.08 blocking findings confirmed actually fixed in `docs/PROTOCOL.md`
§7.5/§7.10 and the `TASK-094`–`TASK-097` files — quoted evidence for each,
no gaps. One cosmetic note raised: §7.10's security-model table didn't have
a dedicated row cross-referencing the new write-count rate limit and the
FILE_MOVE ownership rule (both fixes were correctly present in §7.5, just
not echoed in §7.10's summary table) — added two rows there now for
completeness. No stray references to the old ad-hoc permission scheme
found anywhere in the document.

Both SEC.07 and CQR.08 sign-off requirements for this design are satisfied.
Moving status to `done`. `TASK-094` (SRV.01), `TASK-095` (CLI.02),
`TASK-096` (GUI.03), `TASK-097` (QA.06) are cleared to start per their
`depends_on` edges.
