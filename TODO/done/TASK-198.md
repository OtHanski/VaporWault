---
id:          TASK-198
title:       "Server: permission-safe recursive filename search"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-197]
blocks:      [TASK-199, TASK-201, TASK-202]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, server]
---

Implements `TASK-197`'s wire spec.

**Correction (2026-08-26)**: this Work section still described the
pre-correction cursor-pagination design struck in `TASK-196`/`197`. The
wire spec `TASK-197` actually published has no pagination and no
recursive per-directory tree walk — replaced below with what §7.12 of
`docs/PROTOCOL.md` actually specifies: a single linear scan of the whole
file table (mirroring `vw_store_file_scan_deleted`'s existing idiom),
`effective_permission()` per candidate, and a 200-entry cap +
`truncated` flag instead of a cursor.

## Work

- `SEARCH` handler (`vw_file_handlers.c`): new full-table scan (mirrors
  `vw_store_file_scan_deleted` in `vw_store_files.c`, not a recursive
  per-directory `FILE_LIST`-style walk — there's no `owner_id`-indexed
  enumeration to walk from), calling `effective_permission()` per
  candidate record and reusing its existing visibility logic rather than
  a parallel implementation.
- Case-insensitive substring match against `rec.name` (leaf name only).
- Reject a session-token-only or missing/oversized query
  (`VW_ERR_INVALID_ARG`, >256 bytes) before any table scan.
- Reject scoped (`LINK_ACCESS`-redeemed anonymous) sessions with
  `VW_ERR_PERMISSION` — §7.12 requires a real authenticated session.
- Cap the result set at 200 entries; set `truncated = 1` once the cap is
  hit and stop scanning further (no cursor, no further state to keep
  between calls).
- Register `VW_MSG_SEARCH` in the dispatch switch.

## Security note (`security-sensitive`)

- A match on a file outside the caller's visibility must never be
  observable — not in the result set, not in a count, not in response
  timing that would let a caller binary-search for filenames they can't
  see. Structure the walk so it prunes invisible subtrees the same way
  `FILE_LIST` already does, not "scan everything then filter."
- This is a new parser entry point (query string parsing) — in scope for
  QA.06's standing fuzz-testing policy (`TASK-202`).

## Acceptance criteria

- A user's search never surfaces a filename they don't have view/edit
  access to, including via count or timing side channels — verified
  with a real cross-user test, not just code inspection.
- The 200-entry cap and `truncated` flag behave correctly at the
  boundary (200 vs. 201 matches) and the scan always terminates.
- Malformed query input is rejected cleanly, not a crash or hang.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-08-26]: Implemented per the corrected Work section above.

- `vw_store.h`/`vw_store_files.c`: new `vw_store_file_scan_all()`, the
  non-deleted counterpart to the existing `vw_store_file_scan_deleted()`
  — same locking/callback contract, just `!rec.deleted` instead of
  `rec.deleted`.
- `vw_file_handlers.c`: new `handle_search()` + `search_scan_cb()` +
  `search_name_matches()` (the case-insensitive substring matcher,
  exposed `VW_FH_TESTABLE` for direct unit testing — see
  `vw_file_handlers_internal.h`). Every candidate is permission-checked
  via `effective_permission()` *before* its name is ever compared
  against the query, so a comparison never happens on something the
  caller can't see (the security note's "prune before scanning, don't
  filter after" requirement). Registered `VW_MSG_SEARCH` in
  `vw_server_dispatch_file_op`'s switch (not in `is_write_shaped_msg` —
  it's a read).
- On-wire error convention followed exactly as every other handler in
  this file already does it: failures go out as a separate
  `VW_MSG_ERROR` (`send_error()`), and the real `SEARCH_RESP`'s own
  `error_code` field is only ever `VW_OK` on the success path that
  actually reaches it (matches `LINK_CREATE_ACK`/`LINK_LIST_RESP`'s
  existing convention, not a new one invented here).
- Query >256 bytes rejected before `vw_store_file_scan_all` is ever
  called (`VW_ERR_INVALID_ARG`). Scoped sessions rejected via the
  already-existing `reject_if_scoped()` (`VW_ERR_PERMISSION`), same
  helper `SHARE_GRANT`/`LINK_CREATE` already use.
- Built clean on both toolchains (WSL/GCC `build-gw-e2e`, MSVC
  `build-msvc-105`, Release) after every change in this task, per this
  project's standing two-toolchain verification practice.

**Testing (acceptance criteria)**:

- Unit tests (`tests/unit/test_vw_file_handlers.c`): 5 new cases for
  `search_name_matches()` directly (empty-needle-matches-everything,
  case-insensitive substring, needle-longer-than-haystack, no-match,
  exact-match) — caught and fixed two self-inflicted test bugs while
  writing these (passed an already-uppercased `needle_lc`, violating
  the function's own "caller must pre-lowercase" contract; the haystack
  side's case-insensitivity was already covered by the surrounding
  mixed-case filename, so no coverage was lost fixing it).
- New integration test `tests/integration/test_search.c` +
  `test_search.py` (three real users: owner/grantee/stranger, hand-
  driving the raw `SEARCH`/`SEARCH_RESP` wire message directly via
  `vw_client_conn()` + `vw_proto_send`/`recv`, since no
  `vw_client_search()` wrapper exists yet — that's `TASK-199`). 29
  TAP checks, all real server round-trips, no mocking:
  - owner sees both of their own matching files, `is_shared=0`
  - grantee (VIEW grant on the containing folder) sees only the
    shared file, `is_shared=1` — the owner's other, unshared,
    similarly-named file never appears in any form
  - stranger (zero access) gets `count=0`, `error_code=VW_OK`,
    `truncated=0` — the match is invisible, not merely denied
  - cap boundary: 201 real matching directories → `count=200`,
    `truncated=1` (the acceptance criteria's own named 200-vs-201 case)
  - oversized (300-byte) query → `VW_ERR_INVALID_ARG`
  - a scoped session (real `LINK_ACCESS` redemption) → `VW_ERR_PERMISSION`
  - case-differing query (`FINDME_ALPHA` against lowercase filenames)
  - **Found and fixed a real test-harness bug while first running
    this**: holding 3 client sessions open concurrently hung forever
    against the test server's default `max_workers=2` — restructured
    to close each of grantee/stranger's sessions before opening the
    next, keeping at most 2 concurrent (owner + one other), rather than
    reducing scope to fewer real users.
  - Also fixed a pre-existing binary-discovery gap while wiring this
    up: `test_search.py`'s (and, it turns out, `test_shared_sync.py`'s
    and likely every sibling wrapper's) own binary-search list never
    included `build-gw-e2e/bin` — only `conftest.py`'s newer
    `_find_client_bin` helper (`TASK-161`+) does. Added it to
    `test_search.py`'s own list; did **not** touch the other, older
    wrapper files — that's a real, if minor, pre-existing inconsistency
    across the whole test suite, out of this task's scope to fix
    project-wide. Filing `TASK-217` for BLD.05/QA.06 to reconcile all
    the wrapper files' binary search lists (or replace them with the
    shared `_find_client_bin` helper) in one pass.
- Full regression check: `ctest --test-dir build-gw-e2e` (all 19
  suites) and the full non-cluster pytest integration suite, both green
  after this change (see `TASK-217` for the one adjacent, unrelated gap
  found and filed rather than fixed inline).

Moving to `review`.

SRV.01 [2026-08-26]: Full regression confirmed green before handing off
to review — `ctest --test-dir build-gw-e2e` (19/19 suites) and the full
non-cluster pytest integration suite (`107 passed, 15 deselected`,
including the new `test_search.py`), both run after this task's final
code change (the 201-entry cap-boundary addition to `test_search.c`).

SEC.07 [2026-08-26]: Reviewed `handle_search`/`search_scan_cb` against
the security note and this task's own threat model (new query surface
over potentially-foreign-owned data).

- Confirmed every candidate is run through `effective_permission()`
  before its name is ever compared against the query (line order in
  `search_scan_cb`) — an invisible file never reaches the substring
  comparison, matching FILE_LIST's own "prune before you look" posture
  rather than "scan then filter."
- Confirmed with a real cross-user wire-level test (`test_search.c`),
  not just reading the code: a stranger with zero access gets
  `count=0`/`error_code=VW_OK`/`truncated=0` for a query that has a real
  match elsewhere on the server — the match is genuinely invisible, not
  merely permission-denied (which would itself leak existence).
- Query length bound (256 bytes) enforced before `vw_store_file_scan_all`
  is ever invoked — no way to force a scan with an oversized/pathological
  query. Confirmed by test (300-byte query → `VW_ERR_INVALID_ARG`, no
  scan side effects observed).
- Scoped (anonymous, `LINK_ACCESS`-redeemed) sessions rejected outright
  via the existing, already-reviewed `reject_if_scoped()` — no new
  permission logic to separately audit. Confirmed by test with a real
  redeemed link.
- Result cap (200) is a hard stop inside the scan callback itself (the
  100 s already accepted for `vw_share_scan`) — an attacker cannot force
  unbounded server-side work or an unbounded response via query choice;
  confirmed at the exact 200/201 boundary with a real test.
- No secrets (session tokens, password hashes) ever enter the response
  buffer or get logged; `query`/`query_lc` are stack/struct-local, no
  heap residue beyond the request's own lifetime.
- No blocking findings. Approved.

CQR.08 [2026-08-26]: Reviewed for code quality and consistency with the
rest of `vw_file_handlers.c`.

- Error-code convention matches the file's existing pattern exactly
  (`send_error()`/`VW_MSG_ERROR` for failures; the RESP's own
  `error_code` field is only ever `VW_OK` on the path that reaches it) —
  not a new convention invented for this handler.
- `vw_store_file_scan_all` is a faithful, minimal mirror of
  `vw_store_file_scan_deleted` — same locking discipline, same
  callback contract, one-line condition inverted. No unnecessary
  abstraction introduced.
- `search_name_matches` correctly exposed via the existing
  `VW_FH_TESTABLE`/`vw_file_handlers_internal.h` pattern rather than a
  new one-off testing mechanism.
- Realloc-failure handling in `search_scan_cb` (`if (!p) return 1;`,
  silently ending the scan without marking `truncated`) is inconsistent
  with fully-correct behavior in an OOM edge case, but is byte-for-byte
  the same pattern already accepted in this file's `link_list_cb` — not
  a new gap introduced here, advisory only, not blocking.
- No blocking findings. Approved.
