---
id:          TASK-098
title:       "Server-side vault storage (wrapped keys, opaque encrypted chunks)"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-089]
blocks:      [TASK-101]
review_by:   [SEC.07, CQR.08]
tags:        [server, storage, protocol, security-sensitive]
---

Implement the server side of the E2EE design published in
`docs/PROTOCOL.md` §7.11 (`TASK-089`). The server's role here is
deliberately narrow: store opaque key-wrapping blobs and treat encrypted
chunk content exactly like any other chunk. No content decryption or key
material ever exists server-side.

Scope:

- New vault storage table (`vaults/vaults.db`): vault_id, owner_id,
  folder_file_id, wrapped_vk blob, kdf_salt, kdf_params, created_at.
  Fixed-size record + variable-length blob area for the wrapped key,
  matching this codebase's existing pattern (e.g. `versions.blob`).
- Implement `VAULT_CREATE`/`_ACK`, `VAULT_KEY_FETCH`/`_RESP`, `VAULT_LIST`/
  `_RESP` handlers per §7.11.4. The server must treat `wrapped_vk`/
  `kdf_salt`/`kdf_params` as fully opaque bytes — no parsing, no validation
  beyond size limits.
- Extend `vw_version_record_t` to carry `vault_id` + a reference (offset/
  length into `versions.blob`) to the file's wrapped DEK, reusing the
  existing `_reserved[32]` bytes. Finalize the exact byte layout and get a
  CQR.08 on-disk-compatibility review, matching how `TASK-090`'s
  `deleted_at` reuse was reviewed (confirm `_Static_assert(sizeof(...) ==
  80)` still holds, confirm pre-existing records read back sane defaults).
- Confirm (and note in review) that crash-recovery/oplog replay for
  encrypted files needs zero special-casing — it already operates on
  opaque chunk bytes for every file today.
- Confirm dedup requires no code changes (§7.11.2) — encrypted chunks
  naturally never collide given unique per-file ciphertext. Do not add an
  explicit "is this file encrypted, skip dedup" branch; if you find
  yourself writing one, that's a sign the DEK/nonce scheme upstream (CLI.02,
  `TASK-099`) isn't actually producing unique ciphertext and should be
  flagged back to CLI.02, not worked around server-side.

## Acceptance criteria

- `VAULT_*` messages round-trip correctly against a real client.
- `_Static_assert` confirms `vw_version_record_t`'s size is unchanged; a
  pre-existing (pre-encryption-feature) version record reads back with
  `vault_id == 0` (meaning "not encrypted") cleanly.
- SEC.07 confirms no code path anywhere logs, caches, or otherwise persists
  unwrapped key material or plaintext — the server's crypto-blindness is
  the property being verified here, not just "some encryption happens
  somewhere."

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-089` once its
design was settled and published in `docs/PROTOCOL.md` §7.11.

SRV.01 [2026-07-31]: Implemented per spec.

**New module `vw_vault.h`/`.c`:** fixed-size `vw_vault_record_t` (96 bytes,
`_Static_assert`-enforced) + append-only `vaults.blob` for `wrapped_vk`/
`kdf_params`, same fixed-record-with-guard-slot + append-only-blob pattern
as `vw_share.c`/`vw_store_files.c`. `kdf_salt` is a fixed 16-byte inline
field (Argon2id salt is always 16 bytes per §7.11.4, no need for blob
storage); `wrapped_vk`/`kdf_params` are variable-length and opaque — the
module never parses their content, only enforces a size ceiling
(`VW_VAULT_MAX_WRAPPED_VK_BYTES`/`_KDF_PARAMS_BYTES`) against storage
abuse. `vw_vault_scan()` is a full O(total vaults) scan per `VAULT_LIST`
call, same tradeoff already made for `vw_share_scan()` at this project's
scale — no owner_id index, deliberately, matching that precedent.

**Wire handlers** (`vw_file_handlers.c`): `handle_vault_create`,
`handle_vault_key_fetch`, `handle_vault_list`. `VAULT_CREATE` requires the
caller to own the target `folder_file_id` (`VW_ERR_PERMISSION` otherwise);
`VAULT_KEY_FETCH` requires the caller to own the vault (`VW_ERR_PERMISSION`
if it exists but isn't theirs — same "id exists but isn't yours ->
PERMISSION, not hidden" convention as `SHARE_REVOKE`/`LINK_REVOKE`, since a
`vault_id` is an opaque counter like `share_id`, not something whose mere
existence needs hiding). Both additionally reject a scoped (anonymous)
session outright via the existing `reject_if_scoped` helper, matching
`SHARE_GRANT`/`LINK_CREATE`'s precedent for account-level operations —
`VAULT_LIST` does not, since it naturally returns empty for `user_id == 0`
(no real vault has `owner_id == 0`), matching `SHARE_LIST`'s own precedent
of not needing the explicit check for a pure listing operation.

**`FILE_COMMIT` extension + `vw_version_record_t` layout finalization:**
see `docs/PROTOCOL.md` §7.11.4 for the finalized byte layout (documented
there rather than duplicated here). Implementation notes:
- `vw_store_version_create()`'s signature gained `wrapped_dek`/
  `wrapped_dek_len` parameters; it now appends the wrapped DEK to
  `versions.blob` immediately after that version's chunk hashes in the
  same locked critical section (computing `wrapped_dek_offset` itself,
  same "server always computes blob offsets, never trusts a caller-
  supplied one" convention as `blob_offset`). Rejects a `vault_id`/
  `wrapped_dek` presence mismatch (`VW_ERR_INVALID_ARG`) — either both
  absent or both present, checked in the storage layer itself, not just
  the wire handler, as a defense-in-depth guard against a future caller
  bypassing the handler's own check.
- Added `vw_store_version_get_wrapped_dek()`, mirroring
  `vw_store_version_get_chunks()`'s shape exactly.
- `handle_version_restore` carries `vault_id`/`wrapped_dek` forward
  unchanged when restoring an encrypted version (fetches the old version's
  wrapped DEK and re-appends it as part of the new version record, exactly
  mirroring how it already duplicates `chunk_hashes` into a fresh blob
  region rather than referencing the old one) — restoring re-points HEAD
  at already-encrypted ciphertext, not a new encryption operation, so no
  new DEK is needed or generated, consistent with §7.11.2's "new version
  needs a new DEK" rule applying only to genuinely new content.

**Bug found and fixed while writing the wire handler (in-domain,
`vw_file_handlers.c` is SRV.01's own module):** my first pass used
`VW_ERR_PROTO_INVALID` for `wrapped_vk_len == 0`/oversized values and for
an empty `wrapped_dek` — those are well-formed-but-semantically-invalid
*values*, not malformed *encoding*, and `handle_share_grant` already
established the convention of `VW_ERR_INVALID_ARG` for exactly this
distinction (e.g. an out-of-range permission byte). Fixed both call sites
to match; caught by `test_vault.py::test_vault_create_rejects_empty_
wrapped_vk` asserting the specific code rather than just "some error."

**MSVC build detour (worth recording — cost real time, not a code
defect):** `tests/unit/test_vw_vault.c` failed to compile under MSVC with
a wall of cascading, nonsensical-looking parse errors ("too few arguments
for call" against a call that plainly had the right argument count,
"undeclared identifier" for variables declared two lines above,
"redefinition of `free`"). Root cause: a local variable named `small` —
`<rpcndr.h>` (pulled in transitively by `<windows.h>`, which this test's
existing temp-dir helpers already include on `_WIN32`) `#define`s `small`
to `char` for MIDL/COM compatibility, so `uint8_t small[4]` silently became
`uint8_t char[4]` after macro expansion, and everything downstream was
parsed against a corrupted token stream. GCC/WSL never saw this since it
never includes `<windows.h>`. Renamed the variable; also dropped one
redundant runtime `VW_ASSERT_EQ` against `sizeof(vw_version_record_t)` —
compile-time-constant on both sides, already enforced by the existing
`_Static_assert`, and MSVC's `/W4` flags a compile-time-constant runtime
conditional (`C4127`) as an error under `/WX`. Worth remembering:
`small`/`hyper`/`far`/`near`/`huge` (yes, `huge` too — this file's `huge`
local didn't collide but came close) are all real, still-defined Windows
SDK macros; avoid them as identifiers in any file that might ever include
`<windows.h>`.

**Validation:** `test_vw_vault.c` (26 new test cases covering blob
round-trip, both size ceilings, not-found handling, scan/filter-by-owner,
store-reopen index rebuild, the `vw_version_record_t` layout claim, and the
`vw_store_version_create` wrapped-DEK round-trip + mismatch rejection) —
72 assertions, GCC/WSL and MSVC both clean. `test_vault.py` (11 new
integration tests against a real running server) covers `VAULT_CREATE`/
`_KEY_FETCH`/`_LIST` round-tripping, both ownership checks, the empty-
wrapped_vk rejection, and the `FILE_COMMIT` extension's accept/reject
paths plus the `VERSION_RESTORE` carry-forward path. Full pytest suite (54
tests across all seven integration files) and full `ctest` suite (14
suites) pass with no regressions beyond the pre-existing, unrelated IT-7
quota flake documented in `TASK-095`'s notes. MSVC build of
`vapourwaultd`/`vapourwault-daemon`/`vapourwault-cli`/
`vapourwault-server-cli`/`test_vw_vault` all clean.

**Acceptance criteria check:** `VAULT_*` messages round-trip correctly
against a real client — yes (`test_vault.py`). `_Static_assert` confirms
`vw_version_record_t`'s size is unchanged; a pre-existing version record
reads back with `vault_id == 0` cleanly — yes (`_Static_assert` in
`vw_store.h`, unchanged; explicit test in `test_vw_vault.c`). SEC.07
confirms no code path logs/caches/persists unwrapped key material or
plaintext — see SEC.07's note below.

**Explicitly flagged as open, not silently resolved:** no wire response
today lets a *downloading* client learn a version's `vault_id`/wrapped DEK
— `docs/PROTOCOL.md` §7.11.4 documents this as a known gap for `TASK-099`
to drive the shape of (a client that actually needs to decrypt something
should define what it needs, rather than this task guessing ahead of a
real consumer). `VERSION_RESTORE`'s carry-forward behavior above is
implemented and tested for "doesn't error," but nothing can yet verify the
carried-forward `vault_id` is *retrievable* by a client for the same
reason.

SEC.07 [2026-07-31]: Reviewed every new/changed code path in `vw_vault.c`
and the `FILE_COMMIT`/`VERSION_RESTORE` extensions in
`vw_file_handlers.c`/`vw_store_files.c` for the specific property this
task exists to establish: the server never sees unwrapped key material or
plaintext. Confirmed:
- `wrapped_vk`/`kdf_params`/`wrapped_dek` are treated as pure byte blobs
  everywhere — no parsing, no interpretation, only length checks against
  ceilings and a presence/absence consistency check. No code path
  decrypts, derives a key from, or otherwise interprets these bytes.
- Crash-recovery/oplog replay needs zero special-casing for encrypted
  content, confirmed by inspection — `vw_vault_create`'s oplog entry
  carries only `owner_id` (already-public metadata, same shape as every
  other oplog entry in this codebase), and `vw_store_version_create`'s
  blob-append + record-append sequence treats `wrapped_dek` exactly like
  chunk hashes: opaque bytes written to an append-only file, nothing
  read back and acted on beyond offset/length bookkeeping.
- Dedup requires no code changes, confirmed by inspection of
  `vw_storage.c` (untouched by this task) — encrypted chunks are
  content-addressed by ciphertext SHA-256 exactly like any other chunk;
  uniqueness follows from `TASK-099`'s future per-file DEK generation, not
  from anything server-side.
- No log statement, error message, or admin-visible field anywhere in the
  new code touches `wrapped_vk`/`kdf_params`/`wrapped_dek` content (only
  `vault_id`/`folder_file_id`/`owner_id`/lengths, all already-public
  metadata shapes).
No blocking or advisory findings.

CQR.08 [2026-07-31]: Reviewed the `vw_version_record_t` on-disk
compatibility claim specifically (matching `TASK-090`'s `deleted_at`
precedent this task was asked to follow). Confirmed:
- `_Static_assert(sizeof(vw_version_record_t) == 80, ...)` is unchanged
  and still holds — the new fields exactly fill the former
  `_reserved[32]` (8+8+4+12 = 32 bytes), no size change.
- Every existing write path to this struct (`vw_store_version_create`)
  either explicitly sets the new fields from the caller's `rec` or leaves
  them at whatever `*rec` already had — and every caller constructs `rec`
  via `memset(&rec, 0, sizeof(rec))` first, so any caller that predates
  this task's changes (there are none left uncalled-through, but
  hypothetically) would read back `vault_id == 0` correctly.
- The one asymmetry worth flagging as advisory, not blocking: the
  in-storage-layer `vault_id`/`wrapped_dek` presence-mismatch check in
  `vw_store_version_create` duplicates the wire handler's own check
  (`handle_file_commit` already validates this before calling down).
  Deliberate defense-in-depth per SRV.01's own note above, not an
  oversight — acceptable.
No blocking findings.

ARCH.00 [2026-07-31]: SEC.07 and CQR.08 sign-off received, no blocking
findings. Closing as done. `TASK-101` (E2EE regression tests) may proceed
once `TASK-099` (client vault module) exists — both remain open. `TASK-099`
should read this task's "explicitly flagged as open" note above before
starting: it will need to drive the download-direction wire extension
(surfacing a version's `vault_id`/wrapped DEK to a client) that this task
deliberately left unspecified pending a real consumer.

QA.06 [2026-07-31]: `TASK-101`'s regression suite
(`tests/integration/test_vault_regression.c`/`.py`) directly exercises this
task's storage layer: server opacity (a distinctive plaintext marker
uploaded exclusively as encrypted content is confirmed absent from a raw
black-box scan of the server's entire `data_dir` — chunks, versions.blob,
vaults.blob, all of it) and dedup-defeat across the storage layer's own
chunk-addressing (identical plaintext uploaded plain + into two different
vaults produces three pairwise-distinct stored chunk hashes). Both pass.
No regressions found in this task's own implementation.
