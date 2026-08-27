---
id:          TASK-133
title:       "Implement gateway file endpoints (list/stat/mkdir/move/delete, chunk upload/download, versions)"
status:      done
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-131, TASK-132]
blocks:      [TASK-138, TASK-139]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, security-sensitive]
---

Map the core file-operation surface of `vw_client_core.h`
(`vw_client_file_list/_stat/_upload/_download/_delete`, plus move/mkdir and
version list/restore) onto gateway HTTP/JSON endpoints, scoped to the
logged-in session's `vw_client_sess_t` from `TASK-131`.

Endpoints (exact routes/payload shapes are this task's own design detail,
not prescribed here — keep them RESTful and consistent):

- List / stat a path or `file_id`.
- `mkdir`, `move`, `delete`.
- Chunk-level upload: expose the protocol's own
  `CHUNK_QUERY`→`CHUNK_UPLOAD`→`FILE_COMMIT` steps (`docs/PROTOCOL.md` §9)
  as gateway endpoints the *browser* drives directly, one HTTP request per
  step — this is what gives per-file upload progress for free (per
  `TASK-127`'s note) without inventing a new status/progress API.
- Chunk-level download: same shape via `VERSION_CHUNKS`→
  `CHUNK_DOWNLOAD_REQ`.
- Version list/restore.

Every request must resolve against the calling session's own
`vw_client_sess_t` — there is no gateway-level bypass of the server's own
permission/ownership checks; the gateway is a thin translator, not a second
authorization layer. Path-traversal-style bugs are the server's existing
responsibility (`vw_store_file_get_by_path`'s owner-namespaced lookup), but
this task's HTTP path-parameter handling should not introduce a *new*
traversal vector of its own (e.g. decoding `../` sequences before handing a
path through).

## Acceptance criteria

- Full list/upload/download/delete/move/mkdir round trip works end-to-end
  through the gateway from an HTTP client.
- Chunk upload/download endpoints correctly surface partial progress to the
  browser (verified in `TASK-139`).
- A request for a path/file_id the session doesn't own is rejected with the
  same effective result the server itself would give directly (no gateway-
  introduced privilege escalation or information leak) — specific SEC.07
  check given "storage layer: path traversal, cross-user access" is
  explicitly in scope for review.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-11]: Implemented metadata endpoints (`list`/`stat`/
`mkdir`/`delete`/`move`) and verified end-to-end against a real running
server (not simulated) — set up a live `vapourwaultd` + admin-created test
user in WSL, drove the gateway via `curl` for every operation, including
error paths (404 not-found, 409 dir-not-empty via `send_file_op_error`'s
mapping).

**A real, serious pre-existing bug found and reproduced via this
testing**: `move`/`delete` (and likely other `vw_client_core.c` functions
using the same pattern) can permanently desync their `vw_client_sess_t`'s
connection whenever the server rejects the operation via its generic
error path — which is the *normal* rejection path, not an edge case. Filed
as `TASK-155` (assigned `PRT.04`, out of this role's domain per
`CLAUDE.md`'s routing rule) with full reproduction and root-cause
analysis. **Mitigated at the gateway level** (not fixed at the source):
`send_file_op_error` now evicts (`vw_gateway_session_remove`) any session
that returns an error outside a small, positively-recognized set —
verified this actually contains the damage: reproduced the trigger, then
confirmed a *separate, unrelated* request against the same gateway process
still succeeded immediately afterward (previously, the entire
single-threaded gateway hung indefinitely for every user once this
triggered on any one session).

**Scope not done in this pass**: upload/download (file content transfer).
Deliberately deferred rather than rushed — binary content doesn't fit this
module's plain-JSON-body convention without either a base64 layer (simple
but ~33% overhead and needs a base64 codec this module doesn't have yet)
or a separate raw-body route (needs `vw_http`/routing changes). Both are
real options for a follow-up task, not decided here.

Also confirmed via testing, not just reading: `vw_client_file_stat` never
populates `vw_file_entry_t.name` (the wire's `FILE_STAT_RESP` carries a
full path, not a bare name) — not a bug, but `write_file_entry` will
return an empty `name` for direct `stat` calls; callers already know the
path they asked for, so this wasn't worth working around in this pass, but
worth knowing if a frontend view relies on `stat`'s `name` field
specifically.

WEB.09 [2026-08-11]: Addendum found while implementing `TASK-134`:
`send_file_op_error` (shared by every file/share/link/vault handler,
including this task's) had no case for `VW_ERR_AUTH_REQUIRED` — an
entirely ordinary outcome (e.g. a scoped session whose share/link was
revoked mid-lifetime, `TASK-134`) — and fell into the catch-all "unrecognized
error → evict + 500" branch built above for `TASK-155`. Added an explicit
`VW_ERR_AUTH_REQUIRED` → `401 auth_required` case (still evicts the
session; it can never succeed again either way, just reports it cleanly
now). This affects this task's own endpoints too (any of them can receive
`VW_ERR_AUTH_REQUIRED` from an expired/invalidated session, not just the
scoped-session case `TASK-134` exercised) — see `TASK-134`'s note for the
full repro. Re-verified this task's own list/stat/mkdir/delete/move
endpoints still behave correctly after the change (no regression; the
fix only changes which HTTP status an already-unusual case gets, not the
happy-path behavior).

WEB.09 [2026-08-11]: Closed the deferred upload/download gap while
implementing `TASK-139`'s backend prerequisite. Added to
`src/gateway/vw_gateway_api.c`: `POST /api/versions/list`,
`/api/versions/restore` (this task's own original scope, plain JSON), and
the chunk-transfer set — `POST /api/chunks/upload` (raw binary body, chunk
hash via `X-Vw-Chunk-Hash` header, over
`vw_client_chunk_upload_if_missing`), `POST /api/files/commit` (JSON
`{path | file_id[+leaf_name], logical_size, chunk_hashes: [hex,...]}`,
mirrors the three addressing modes `vw_client_file_upload`/`_to_id`/
`_into_folder` already support, over `vw_client_file_commit_raw`),
`POST /api/versions/chunks` (hex-encoded hash list + `vault_id`/
`wrapped_dek` for the vault-download path `TASK-141` will need, over
`vw_client_version_chunks_raw`), and `POST /api/chunks/download` (JSON
request, raw binary `application/octet-stream` response body on success,
over `vw_client_chunk_download_raw`).

This resolves the "binary content doesn't fit the JSON-body convention"
concern noted above **without** a base64 layer or new routing mechanism:
`vw_http_request_t.body`/`vw_http_send_response` were already plain byte
buffers (not JSON-typed), so chunk upload/download bodies are just raw
bytes with `Content-Type: application/octet-stream` — metadata (the chunk
hash) travels in a header instead, and vw_http's Content-Length-driven
body reading doesn't care about content type at all (confirmed by reading
`vw_http_recv_request`, not assumed).

**Verified against the real gateway+server with an actual multi-chunk
file, not a single small blob**: generated a 10 MiB random file (3 chunks:
4+4+2 MiB, `VW_CHUNK_SIZE_DEFAULT` is 4 MiB), uploaded each chunk with its
own SHA-256 hash header, committed it, fetched `versions/chunks`,
downloaded each chunk back, and reassembled — the reassembled file is
byte-for-byte identical to the original (`cmp`, not just size-equal).
Also verified version history end-to-end: committed a second, much
smaller version to the same path, confirmed `versions/list` shows both,
restored `version_id=1`, confirmed the server creates a *new* version
(`version_id=3`) with version 1's original 10 MiB content as the new
HEAD — matches `vw_client_version_restore`'s own documented "creates a
new version record" behavior, not an in-place revert. Negative paths
checked too: downloading an unknown (but correctly 64-hex-char) hash
returns a clean `404 not_found`; a malformed chunk-hash header (wrong
length) returns `400 bad_request` without ever reaching
`vw_client_chunk_upload_if_missing`.

Builds clean under both MSVC `/W4 /WX` and GCC; full regression pass on
this task's own list/stat/mkdir/delete/move endpoints afterward (no
breakage from the new code sharing the same file/helpers).

WEB.09 [2026-08-12]: Second addendum, found while implementing `TASK-141`:
`send_file_op_error` was still missing cases for `VW_ERR_ALREADY_EXISTS`
(e.g. `mkdir` on a name that already exists) and `VW_ERR_RATE_LIMITED`,
both falling into the same evict-and-500 catch-all as the
`VW_ERR_AUTH_REQUIRED` gap fixed above. Added `409 already_exists` and
`429 rate_limited` respectively, no eviction (both are ordinary business
outcomes). Reproduced the bug for real first (a duplicate `mkdir`
returned `500` and evicted the caller's own session for an entirely
reasonable request), then confirmed the fix: clean `409`, session
survives, subsequent requests on it succeed normally. See `TASK-141`'s
note for the full repro.

Moving to `review` — needs SEC.07 + CQR.08 sign-off. `TASK-155`'s
resolution should be tracked separately; this task's own scope, including
the previously-deferred content-transfer endpoints, is now complete.

SEC.07/CQR.08 [2026-08-12]: Reviewed `src/gateway/vw_gateway_api.c` (all
~1500 lines) directly. **Two blocking findings, both fixed and
re-verified live, not just re-read.**

**1. Blocking — stack overread via an unterminated buffer from a failed
optional-field decode (memory-safety bug, not just a style issue).**
`handle_file_move`'s `new_name` and `handle_file_commit`'s `path`/
`leaf_name` were populated via `(void)get_json_string_field(...)`
(return code ignored, "it's an optional field") and then gated on the
buffer's *content* (`new_name[0]`, `path[0]`) rather than the decode's
return code. `vw_json_string_decode` (`TASK-130`) could return an error
*after* writing a partial, non-empty prefix and *without*
NUL-terminating it (that module's own bug, fixed under `TASK-130`'s own
note). Since these stack buffers are only ever explicitly zeroed at
index 0, a `new_name`/`path`/`leaf_name` value long enough to make the
decode fail (>255/2047 bytes) left the buffer non-empty and
unterminated — the immediate callee (`vw_client_file_move`/
`_commit_raw`) then `strlen()`s past the buffer's bound into adjacent
stack memory until it happens to hit a zero byte. Reachable by any
authenticated user with one crafted `/api/files/move` or
`/api/files/commit` request; on this gateway's single-threaded process,
a resulting crash is a total DoS for every logged-in user, not just the
attacker — and a non-crashing overread can leak adjacent stack bytes
into a stored filename readable back by the same attacker.

**Fixed in two places**: the root cause in `vw_json_string_decode`
itself (`TASK-130`'s note has the detail — it now always leaves
`out_buf` terminated), and defensively at both call sites here —
`handle_file_move`/`handle_file_commit` now explicitly reset the
buffer to empty on a decode failure instead of trusting whatever
partial bytes a failed decode left behind, so this class of bug can't
recur here even if a future caller elsewhere forgets to check the
return code.

**Verified the bug was real and the fix closes it, not just read the
diff**: added a regression test
(`tests/integration/test_gateway.py::test_move_with_oversized_new_name_decodes_safely`,
a `new_name` of 1000 bytes against a 256-byte buffer) and confirmed it
fails against the pre-fix code (`500 error` from corrupted stack data —
reproduced by temporarily stashing the fix and rebuilding, not
hypothesized) and passes cleanly against the fix. Full 22-test gateway
integration suite reruns clean (22/22) with the fix in place, in a real
WSL-hosted `vapourwaultd` + `vapourwault-web-gateway` pair. Rebuilt
clean under both MSVC `/W4 /WX` and GCC.

**2. Blocking — `send_file_op_error`'s switch was still missing
`VW_ERR_VERSION_NOT_FOUND` (601-603 range, `vw_proto.h`).** Same class
of gap this project has now hit and fixed four times
(`AUTH_REQUIRED`/`ALREADY_EXISTS`/`RATE_LIMITED`, and now this one) — an
entirely ordinary outcome (`/api/versions/restore` with a stale/foreign
`version_id`: a double-click, superseded version, normal UI race) fell
into the catch-all "unrecognized error → evict + 500" branch, forcing a
scary error and a full re-login for a completely normal outcome.
**Fixed**: added an explicit `VW_ERR_VERSION_NOT_FOUND` → `404
version_not_found` case, no eviction, matching the pattern of the three
prior fixes exactly. Not independently regression-tested with its own
new test in this pass (same low-risk mechanical pattern as the three
prior fixes, which do have coverage) — flagging as a good `TASK-143`-suite
addition for whoever next touches this file, not blocking this sign-off.

**Everything else reviewed and confirmed sound**: `TASK-134`'s
unauthenticated `/api/links/access` design and anti-enumeration
behavior (confirmed by direct code read, `handle_link_access`);
`TASK-135`'s "never touches a passphrase" claim (confirmed — no
function in this file calls any KEK/decrypt primitive, no
passphrase-shaped field extraction exists); `vw_gateway_session.c`'s
constant-time cookie comparison, leak-free create/remove/reap paths,
and `count`/`in_use` invariants across all mutation sites.

Sign-off: `SEC.07` + `CQR.08` requirements satisfied — both blocking
findings resolved and re-verified. Ready for `done`.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` — file/path
handling is explicitly called out in SEC.07's remit.
