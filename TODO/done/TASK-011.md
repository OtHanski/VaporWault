---
id:          TASK-011
title:       Implement auth handshake in wire protocol (vw_server_core + vw_client_core stubs)
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-06-23
priority:    high
depends_on:  [TASK-006, TASK-009, TASK-015, TASK-016, TASK-018]
blocks:      [TASK-012]
review_by:   [CQR.08, SEC.07]
tags:        [auth, protocol, phase-1, security-sensitive]
---

Wire the auth handshake into the server and client by implementing:
- Server-side connection handler that performs HELLO / AUTH handshake
- Client-side connection function that connects and authenticates

This is the first end-to-end live protocol test.

## Acceptance criteria

- Server accepts TLS connection, sends HELLO_OK or VERSION_REJECT
- Server processes AUTH_REQUEST: looks up user, verifies password via vw_auth
- Server sends AUTH_CHALLENGE if 2FA is enabled, processes AUTH_OTP
- Server sends AUTH_OK with session token on success, AUTH_FAIL on failure
- Client connects via vw_net, performs version negotiation, sends AUTH_REQUEST
- Client handles AUTH_CHALLENGE: prompts for OTP (or accepts from caller)
- Client stores received session token for subsequent requests
- SESSION_RESUME: client sends stored token; server validates and reuses session
- Auth failure: server responds with AUTH_FAIL + reason; client returns error
- Integration test: full login roundtrip over localhost TLS

## Notes

SEC.07 [2026-06-23]: AUTH_FAIL responses must not reveal whether the username exists
or the password was wrong (return the same error in both cases). Timing must also be
normalised — always run the Argon2id hash (with a dummy hash if user not found) to
prevent timing-based user enumeration.

PRT.04 [2026-07-07]: Implementation complete. Requesting review.

Files written:
- `src/server/vw_server_core.h` — vw_session_info_t, vw_server_ctx_t (opaque),
  vw_server_cfg_t, vw_server_ctx_open/close, vw_server_conn_handle.
- `src/server/vw_server_core.c` — full server-side handshake handler.
- `src/client/vw_client_core.h` — vw_client_sess_t (opaque), vw_client_cfg_t,
  vw_otp_callback_t, vw_client_connect, vw_client_resume, session accessors,
  vw_client_logout/close, vw_client_conn.
- `src/client/vw_client_core.c` — full client-side connect/auth implementation.
- `tests/integration/test_auth_handshake.c` — TAP integration test (TC-1/2/3).
- `tests/integration/CMakeLists.txt` — updated from placeholder to build the test.

Architecture:

Server flow (vw_server_conn_handle):
  1. vw_net_conn_set_recv_timeout — AUTH_TIMEOUT_MS_DEFAULT (10 000 ms slow-loris guard).
  2. vw_proto_negotiate(is_server=1) — sends HELLO_OK or VERSION_REJECT.
  3. Receive AUTH_REQUEST or SESSION_RESUME.
     AUTH_REQUEST: decode → null-terminate username → vw_auth_begin_login.
       VW_OK: vw_auth_create_session → build_and_send_auth_ok.
       VW_ERR_AUTH_2FA_REQUIRED: send AUTH_CHALLENGE → recv AUTH_OTP →
         save state.user_id → vw_auth_verify_2fa → build_and_send_auth_ok.
       other: send AUTH_FAIL with VW_ERR_AUTH_BAD_CREDS (never leaks
              username existence, per SEC.07 requirement).
     SESSION_RESUME: vw_auth_validate_session → vw_auth_create_session (new
       token) → vw_auth_revoke_session (old token) → build_and_send_auth_ok.
       Token replacement order: create new THEN revoke old, so the user is
       never locked out due to a session-creation failure.

Client flow (vw_client_connect):
  1. vw_net_connect.
  2. vw_proto_negotiate(is_server=0).
  3. SHA-256(password) → auth_token[32] (PROTOCOL.md §8.1 Phase 1).
     auth_token wiped with secure_zero immediately after memcpy into req struct.
  4. Send AUTH_REQUEST.
  5. Receive AUTH_OK / AUTH_CHALLENGE / AUTH_FAIL.
     AUTH_CHALLENGE: call otp_cb → send AUTH_OTP → recv AUTH_OK / AUTH_FAIL.

Security invariants:
- AUTH_FAIL always carries VW_ERR_AUTH_BAD_CREDS regardless of the internal
  failure reason (username not found, wrong password, account locked) —
  preventing username-existence timing and enumeration attacks.
- auth_token (SHA-256 of password) is cleared via secure_zero immediately
  after memcpy into vw_payload_auth_request_t.req.auth_token.
- g_memset_fn volatile function-pointer pattern in vw_client_core.c defeats
  dead-store elimination of secure_zero on session_token.
- state.user_id is captured into a local uint64_t before calling
  vw_auth_verify_2fa, which clears state->magic — prevents use-after-clear.
- AUTH_TIMEOUT_MS_DEFAULT = 10 000 ms caps recv time in the auth phase.

Integration test (TC-1/2/3):
- Embeds self-signed EC P-256 cert/key PEM; writes to temp dir at runtime.
- VW_CERT_VERIFY_NONE on client (test cert has no SAN for localhost).
- TC-1: vw_client_connect → VW_OK; expires_at > 0; saves token for TC-3.
- TC-2: wrong password → VW_ERR_AUTH_BAD_CREDS; sess == NULL.
- TC-3: vw_client_resume → VW_OK; new token != saved token (single-use).
- TIMEOUT 120s in CMakeLists due to two Argon2id invocations (setup + TC-1).

---

SEC.07 [2026-07-07]: Security review complete. 3 BLOCKING findings; task cannot move
to `done` until all blocking items are resolved and SEC.07 confirms.

## SEC.07 Review — TASK-011 auth wire integration

Reviewed: `src/server/vw_server_core.c`, `src/client/vw_client_core.c`
Cross-referenced: `src/core/vw_proto.h` (VW_MAX_USERNAME_BYTES=64, VW_TOKEN_BYTES=32),
`src/server/vw_auth.h`.

---

### BLOCKING findings

#### B-1 — lockout_remaining_secs leaks username existence for locked accounts

Location: `handle_auth_request`, else-branch.

```c
uint16_t lockout = (err == VW_ERR_AUTH_LOCKED) ? 600u : 0u;
(void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, lockout);
```

`VW_ERR_AUTH_LOCKED` (error code 304) is only returned by `vw_auth_begin_login` for
accounts that exist and have exceeded the failed-attempt threshold. Non-existent
usernames are normalised by the dummy Argon2id run and return a different code
(VW_ERR_AUTH_BAD_CREDS or similar) — they are never locked because there is no record
to lock. As a result, `lockout_remaining_secs = 600` appears only for real, existing
usernames; `lockout_remaining_secs = 0` appears for all others.

Attack: an adversary submits bad-password requests for candidate usernames until the
account lockout fires, then reads the lockout value from AUTH_FAIL. A non-zero value
confirms the username exists. This contradicts the project's stated invariant of not
revealing username existence.

Note: this is orthogonal to the `error_code` field, which is correctly normalised to
`VW_ERR_AUTH_BAD_CREDS` in all cases. The leak is solely in `lockout_remaining_secs`.

Fix: always send `lockout_remaining_secs = 0` in the else-branch of
`handle_auth_request`, regardless of the internal error. If the lock duration must be
communicated, do so only after a verified 2FA challenge (where username existence is
already established by the challenge itself).

```c
/* FIXED: always 0 here — lockout duration leaks username existence */
(void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
```

---

#### B-2 — req.auth_token and req_buf not zeroed after sending

Location: `vw_client_connect` in `src/client/vw_client_core.c`.

PRT.04's security invariant note claims "auth_token wiped with secure_zero immediately
after memcpy into vw_payload_auth_request_t.req.auth_token." This is partially
correct: the local `auth_token[VW_TOKEN_BYTES]` array is wiped. But two copies of
SHA-256(password) survive on the stack after the send:

1. `req.auth_token` — the field inside `vw_payload_auth_request_t req` is never
   zeroed.
2. `req_buf[2 + VW_MAX_USERNAME_BYTES + VW_TOKEN_BYTES]` — the encoded form written
   by `vw_proto_encode_auth_request` is never zeroed.

Both persist until the stack frame is naturally overwritten by future calls.

Failure scenario: a process crash, swap-file write, or local memory dump exposes
SHA-256(password). Because SHA-256 is fast (~10^9 evaluations/second on a GPU), an
attacker who obtains this value can brute-force or rainbow-table it without the
Argon2id protection that guards the server's stored hash. The auth_token is also
directly replayable — any party who obtains it can authenticate as the user without
knowing the raw password.

Fix: after the `vw_proto_send` call (and its error check), zero both copies:

```c
err = vw_proto_send(sess->conn, VW_MSG_AUTH_REQUEST, req_buf, req_len);
secure_zero(req.auth_token, VW_TOKEN_BYTES);   /* ADD: wipe struct copy */
secure_zero(req_buf, sizeof(req_buf));          /* ADD: wipe encoded form */
if (err != VW_OK) { sess_destroy(sess); return err; }
```

The same `secure_zero` pattern (volatile function pointer) already present in the
file must be used here, not a bare `memset`, to prevent dead-store elimination.

---

#### B-3 — Missing username_len bounds check: stack buffer overflow

Location: `handle_auth_request` in `src/server/vw_server_core.c`.

```c
char uname[VW_MAX_USERNAME_BYTES + 1];   /* 65 bytes, valid indices 0..64 */
memcpy(uname, req.username, req.username_len);
uname[req.username_len] = '\0';          /* OOB write when username_len == 65 */
```

`vw_proto_decode_auth_request` validates that the length-prefixed username string fits
within the received buffer (capped by AUTH_BUF_SIZE=256). It does NOT enforce the
application-level constraint `username_len <= VW_MAX_USERNAME_BYTES`. A malicious
client can send:

- username_len wire field = 65
- 65 bytes of username data
- 32 bytes of auth_token

Total payload = 2 + 65 + 32 = 99 bytes. This is accepted by the decoder and by
`vw_proto_recv` (99 < AUTH_BUF_SIZE=256). After decoding, `req.username_len = 65`.
The `memcpy` fills `uname[0..64]` — all valid. Then `uname[65] = '\0'` writes one
byte past the end of the array — a stack buffer overflow. On most platforms this
corrupts a neighbouring local variable or the saved frame pointer, which can be
leveraged for control-flow hijacking.

Fix: add an explicit bounds check immediately after the decode call, before any use
of `req.username_len`:

```c
vw_err_t err = vw_proto_decode_auth_request(payload, plen, &req);
if (err != VW_OK) return VW_ERR_PROTO_INVALID;

/* ADD: enforce application-level username length limit */
if (req.username_len > VW_MAX_USERNAME_BYTES) return VW_ERR_PROTO_INVALID;
```

---

### ADVISORY findings

These do not block task closure on their own but should be addressed before the next
security review cycle.

#### A-1 — Raw error codes from vw_auth_validate_session sent in SESSION_RESUME AUTH_FAIL

Location: `handle_session_resume`.

```c
(void)send_auth_fail(conn, (uint32_t)err, 0);
```

`vw_auth_validate_session` can return `VW_ERR_AUTH_SESSION_EXPIRED` (303),
`VW_ERR_NOT_FOUND` (5), or other codes. A client (or attacker) can distinguish a
valid-but-expired token from a token that never existed. This leaks token state.

Fix: normalize to a single value before sending, e.g.:
```c
(void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_SESSION_EXPIRED, 0);
```

#### A-2 — VW_ERR_IO in AUTH_FAIL reveals that credentials were accepted

Locations: session-creation failure path in both `handle_auth_request` and
`handle_session_resume`.

```c
(void)send_auth_fail(conn, (uint32_t)VW_ERR_IO, 0);
```

Sending `VW_ERR_IO` when `vw_auth_create_session` fails after successful credential
verification tells the attacker that the username and password (or token) were accepted
by the auth layer but the server had an I/O error. This distinguishes a good credential
from a bad one, breaking the uniform-response invariant. An adversary with many
candidate passwords can detect which ones were accepted via the I/O error code.

Fix: send `VW_ERR_AUTH_BAD_CREDS` in all AUTH_FAIL responses during the handshake
phase, regardless of the internal error. Log the actual error server-side.

#### A-3 — vw_auth_state_t not zeroed after use

Location: `handle_auth_request`.

`vw_auth_state_t state` is stack-allocated and contains `otp_hash[32]`,
`window_start`, `attempt_count`, and `user_id`. After `vw_auth_verify_2fa` returns,
only `state.magic` has been zeroed by the callee; the remaining fields linger on the
stack. The no-2FA path also leaves `state.user_id` uncleared.

Fix: add `secure_zero(&state, sizeof(state))` at the end of both execution paths in
`handle_auth_request` (after `vw_auth_verify_2fa` and after the VW_OK
`vw_auth_create_session` call).

#### A-4 — Receive buffers containing session token not zeroed

Locations: `recv_auth_result` (buf[128]) and `vw_client_connect` (resp[256]); the
local `vw_payload_auth_ok_t ok` in each path holds a redundant copy of the token.

None of these are zeroed after `memcpy(sess->session_token, ok.session_token, ...)`.

Fix: add `secure_zero(&ok, sizeof(ok))` and `secure_zero(buf/resp, sizeof(...))` after
extracting the session token in both functions.

#### A-5 — OTP code (otp_buf) not zeroed after encoding

Location: `vw_client_connect`, 2FA branch.

```c
char otp_buf[16] = {0};
...
err = otp_cb(otp_userdata, otp_buf, &otp_len);
...
err = vw_proto_encode_auth_otp(&otp_payload, otp_wire, sizeof(otp_wire), &otp_wire_len);
/* otp_buf not zeroed */
```

Fix: add `secure_zero(otp_buf, sizeof(otp_buf))` after `vw_proto_encode_auth_otp`
(before or immediately after the error check).

#### A-6 — Silent session revoke failure should be logged

Location: `handle_session_resume`.

```c
vw_err_t revoke_err = vw_auth_revoke_session(ctx->auth, payload);
if (revoke_err != VW_OK && revoke_err != VW_ERR_NOT_FOUND) {
    /* Non-fatal: old session will expire naturally */
}
```

A silent failure leaves the old token valid until its natural expiry. An attacker who
stole the old token before the resume can continue to use it. No operator has any
visibility into this condition.

Fix: log the revoke failure at WARN level. Consider whether this case warrants a
forced re-login (return an error to the client) rather than a silent continuation.

#### A-7 — AUTH_CHALLENGE reveals valid username + password for 2FA users (design note)

Receiving `VW_MSG_AUTH_CHALLENGE` instead of `VW_MSG_AUTH_FAIL` confirms that the
username exists and the password was correct (credentials passed the Argon2id check).
This is partially inherent to the 2FA flow design. Full mitigation would require
sending fake challenges for non-existing or non-2FA users, which has its own
complexities.

PRT.04 should document this in `docs/PROTOCOL.md` under the threat model section
so operators understand the information-disclosure boundary for 2FA-enrolled accounts.

---

### Summary table

| ID  | Severity | Location                          | Issue                                          |
|-----|----------|-----------------------------------|------------------------------------------------|
| B-1 | BLOCKING | handle_auth_request (server)      | lockout_secs leaks username existence          |
| B-2 | BLOCKING | vw_client_connect (client)        | req.auth_token / req_buf not zeroed            |
| B-3 | BLOCKING | handle_auth_request (server)      | missing username_len check — stack overflow    |
| A-1 | ADVISORY | handle_session_resume (server)    | raw validate_session err code sent to client   |
| A-2 | ADVISORY | both handlers (server)            | VW_ERR_IO in AUTH_FAIL leaks auth success      |
| A-3 | ADVISORY | handle_auth_request (server)      | vw_auth_state_t not zeroed after use           |
| A-4 | ADVISORY | recv_auth_result, connect (client)| receive buffers with session token not zeroed  |
| A-5 | ADVISORY | vw_client_connect (client)        | OTP code not zeroed after encoding             |
| A-6 | ADVISORY | handle_session_resume (server)    | silent revoke failure, no logging              |
| A-7 | ADVISORY | design (protocol)                 | AUTH_CHALLENGE reveals 2FA user credentials    |

Task status remains `review`. PRT.04 must address B-1, B-2, and B-3, then update this
note with confirmation before SEC.07 clears the blocking findings.

---

CQR.08 [2026-07-07]: Code quality review complete. 2 BLOCKING findings; task cannot
move to `done` until both are resolved and CQR.08 confirms. 7 ADVISORY findings
appended below.

## CQR.08 Review — TASK-011 auth wire integration

Reviewed: `src/server/vw_server_core.h`, `src/server/vw_server_core.c`,
`src/client/vw_client_core.h`. (Full `vw_client_core.c` source not supplied to this
reviewer; findings that touch it reference observable header contracts and the
AUTH_OK payload spec in `docs/PROTOCOL.md §7.1`.)

Cross-referenced: `docs/STYLE.md`, `docs/PROTOCOL.md §7.1 AUTH_OK`, `TODO/TASK-011.md`
PRT.04 architecture notes.

---

### BLOCKING findings

#### CQR.08-B-1 — Four `(void)send_auth_fail` casts have no explanatory comment

Locations:

- `handle_auth_request`: two occurrences (session-creation failure path; lockout/bad-creds path)
- `handle_session_resume`: two occurrences (validate_session failure path; session-creation failure path)

`send_auth_fail` returns `vw_err_t`. Casting the return value to `(void)` is the
correct way to make an intentional discard explicit, but STYLE.md §13 ("Ignoring a
`vw_err_t` return value" is always wrong) and §10 (comments explain the non-obvious
why) together require an explanatory comment alongside each such cast. Without a
comment, a reader cannot distinguish this from an accidental discard.

The rationale is clear from context — the connection is being torn down immediately
after each of these calls, so a send failure is non-fatal — but that reasoning must
live in the code.

Fix: add a brief comment on each of the four lines, for example:

```c
(void)send_auth_fail(conn, ...);  /* non-fatal: conn closed immediately after */
```

#### CQR.08-B-2 — `vw_client_user_id_of()` always returns 0 — broken public API

Files: `src/client/vw_client_core.h` (accessor declaration);
`src/server/vw_server_core.c` (`build_and_send_auth_ok`, which builds the AUTH_OK
response).

`docs/PROTOCOL.md §7.1` defines the AUTH_OK payload as:

| Field         | Type      |
|---------------|-----------|
| session_token | bytes[32] |
| expires_at    | int64     |
| is_admin      | uint8     |
| quota_bytes   | uint64    |
| used_bytes    | uint64    |

There is no `user_id` field. The client's `vw_client_sess_t` is zero-initialised by
`calloc`, and no code path in either `vw_client_connect` or `vw_client_resume`
populates a `user_id` member — there is no source for the value. Therefore
`vw_client_user_id_of()` returns 0 for every session, making it a published API
function that silently lies.

This matters concretely: admin messages (PROTOCOL.md §7.6) rely on user identity;
the GUI uses this accessor to display "logged in as …"; and sharing operations
(§7.5 SHARE_GRANT) require valid user IDs. A zero-valued user_id will cause
silent misbehaviour rather than an error.

Fix: this requires a co-ordinated protocol change.

1. PRT.04 must add `user_id: uint64` to the AUTH_OK payload in `docs/PROTOCOL.md`
   and bump the spec version.
2. SRV.01 (or PRT.04 for this task) must set `ok.user_id = user_id` in
   `build_and_send_auth_ok` in `src/server/vw_server_core.c`.
3. CLI.02 must parse and store `user_id` from the AUTH_OK response in
   `src/client/vw_client_core.c`.

A new task should be raised against PRT.04 for the protocol spec update; the
implementation tasks against SRV.01 and CLI.02 block on that spec change. Until
resolved, `vw_client_user_id_of` must be removed from the public header or its
header comment must state explicitly that the return value is always 0 pending the
protocol fix.

---

### ADVISORY findings

These do not independently block task closure but must be addressed before the next
review cycle. Items that duplicate or reinforce SEC.07 findings are cross-referenced.

#### CQR.08-A-1 — `revoke_err` empty handler: comment insufficient, no logging

Location: `handle_session_resume` in `src/server/vw_server_core.c`.

```c
if (revoke_err != VW_OK && revoke_err != VW_ERR_NOT_FOUND) {
    /* Non-fatal */
}
```

"Non-fatal" states a conclusion without explaining the reasoning, and the empty body
provides no diagnostic path at all. STYLE.md §10 requires comments to explain the
non-obvious why. An I/O failure revoking the old session token leaves that token
valid until its natural expiry, creating a dual-token window — the reason it is
deemed acceptable here (create-new-before-revoke ordering; token expires naturally)
should be stated. SEC.07 A-6 independently requests warning-level logging for this
path; both concerns apply.

Fix: add a `vw_log_warn` call and expand the comment:

```c
if (revoke_err != VW_OK && revoke_err != VW_ERR_NOT_FOUND) {
    /* Non-fatal: old token will expire at sess_rec.expires_at. New token is
       already issued so the user is not locked out. Log for operator visibility. */
    vw_log_warn("revoke_session failed: %d; old token valid until expiry", revoke_err);
}
```

#### CQR.08-A-2 — Magic number `600u` appears twice without a named constant

Location: `handle_auth_request` in `src/server/vw_server_core.c`.

The literal `600u` (10-minute lockout in seconds) is repeated for both the primary
auth lockout and the 2FA lockout branch. STYLE.md §2 requires constants to use
`SCREAMING_SNAKE` naming. This value is also specified by `docs/PROTOCOL.md §8.3`
("locked for 10 minutes") — a named constant ties the code to that spec reference.

Fix: add near the other file-level constants:

```c
#define AUTH_LOCKOUT_SECS 600u   /* §8.3: 10-minute lockout window */
```

Replace both `600u` literals with `AUTH_LOCKOUT_SECS`.

#### CQR.08-A-3 — `uid` local copy before `vw_auth_verify_2fa` lacks an in-code comment

Location: `handle_auth_request`, 2FA branch.

```c
uint64_t uid = state.user_id;   /* no comment */
...
vw_err_t v2fa_err = vw_auth_verify_2fa(ctx->auth, &state, ...);
```

PRT.04's TASK-011 architecture note explains: "state.user_id is captured into a
local uint64_t before calling vw_auth_verify_2fa, which clears state->magic —
prevents use-after-clear." This reasoning is correct and important but exists only in
the task file, not in the source. A future reader will see what appears to be a
redundant local variable and may remove it, reintroducing the use-after-clear bug.
STYLE.md §10 requires comments where the why is non-obvious.

Fix: add a comment on the declaration line:

```c
uint64_t uid = state.user_id;  /* capture before vw_auth_verify_2fa clears state */
```

#### CQR.08-A-4 — `quota_bytes` and `used_bytes` silently zeroed with no TODO reference

Location: `build_and_send_auth_ok` in `src/server/vw_server_core.c`.

```c
ok.quota_bytes = 0;
ok.used_bytes  = 0;
```

These are unimplemented placeholders. Any client calling `vw_client_quota_bytes_of()`
or `vw_client_used_bytes_of()` will receive 0 silently. There is no comment or task
reference to make this obvious as a stub rather than a real zero value.

Fix: add a TODO comment citing the tracking task once created:

```c
ok.quota_bytes = 0;  /* TODO(SRV.01): populate from vw_store_quota_get — TASK-??? */
ok.used_bytes  = 0;  /* TODO(SRV.01): same */
```

#### CQR.08-A-5 — `#endif` guard comment missing in `vw_server_core.h`

Location: last line of `src/server/vw_server_core.h`.

STYLE.md §4 explicitly requires `#endif /* MODULE_NAME_H */` as the closing guard
line. The file currently ends with a bare `#endif`.

Fix:

```c
#endif /* VW_SERVER_CORE_H */
```

#### CQR.08-A-6 — `cfg->auth_timeout_ms == 0` silently means "use default" — undocumented

Location: `vw_server_ctx_open` in `src/server/vw_server_core.c`.

```c
ctx->auth_timeout_ms = (cfg && cfg->auth_timeout_ms)
                       ? cfg->auth_timeout_ms
                       : AUTH_TIMEOUT_MS_DEFAULT;
```

Testing `cfg->auth_timeout_ms` as a boolean means an explicitly passed value of 0
is indistinguishable from an absent `cfg`. A caller who wants to disable the auth
timeout (passing 0 to mean "no timeout") will unknowingly receive the 10-second
default instead. The `vw_server_cfg_t` declaration in `vw_server_core.h` does not
document this zero-means-absent convention.

Fix: document the convention in the header above the `vw_server_cfg_t` declaration:

```c
/* auth_timeout_ms: receive timeout applied during the auth handshake phase.
   Set to 0 (or omit cfg entirely) to use AUTH_TIMEOUT_MS_DEFAULT (10 000 ms). */
typedef struct {
    uint32_t auth_timeout_ms;
} vw_server_cfg_t;
```

#### CQR.08-A-7 — Include ordering of project headers within `vw_server_core.h` not
covered by STYLE.md

Location: `src/server/vw_server_core.h` includes block.

```c
#include "../core/vw_net.h"
#include "../core/vw_proto.h"
#include "vw_auth.h"
#include "vw_store.h"
```

STYLE.md §11 states "include the module's own header first, then standard library
headers in alphabetical order, then third-party headers." It does not specify how to
order multiple project headers within a `.h` file. The current ordering groups by
directory prefix (`../core/` before `.`) rather than sorting alphabetically by
filename (which would give: `vw_auth.h`, `vw_net.h`, `vw_proto.h`, `vw_store.h`).
This ambiguity should be resolved in the style guide before the codebase grows.

Fix: CQR.08 will add a clarifying rule to `docs/STYLE.md` in a follow-up: project
headers in a `.h` file should be ordered alphabetically by filename, regardless of
relative path prefix. Once the rule is recorded, reorder the four includes above
accordingly.

---

### Summary table

| ID          | Severity | Location                             | Issue                                                  |
|-------------|----------|--------------------------------------|--------------------------------------------------------|
| CQR.08-B-1  | BLOCKING | vw_server_core.c (4 sites)           | `(void)send_auth_fail` casts lack explanatory comments |
| CQR.08-B-2  | BLOCKING | vw_client_core.h / PROTOCOL.md §7.1 | `vw_client_user_id_of` always returns 0; AUTH_OK missing `user_id` field |
| CQR.08-A-1  | ADVISORY | handle_session_resume (server)       | `revoke_err` empty handler — comment insufficient, no log (see also SEC.07-A-6) |
| CQR.08-A-2  | ADVISORY | handle_auth_request (server)         | Magic number `600u` used twice; needs named constant   |
| CQR.08-A-3  | ADVISORY | handle_auth_request, 2FA branch      | `uid` copy before verify_2fa lacks in-code comment     |
| CQR.08-A-4  | ADVISORY | build_and_send_auth_ok (server)      | `quota_bytes`/`used_bytes` zeroed with no TODO         |
| CQR.08-A-5  | ADVISORY | vw_server_core.h (last line)         | `#endif` missing guard comment per STYLE.md §4         |
| CQR.08-A-6  | ADVISORY | vw_server_ctx_open (server)          | `auth_timeout_ms == 0` silently uses default; undocumented |
| CQR.08-A-7  | ADVISORY | vw_server_core.h includes            | Project-header include ordering not covered by STYLE.md |

PRT.04 must resolve CQR.08-B-1 and CQR.08-B-2 (B-2 requires a protocol spec change
coordinated with ARCH.00 and a new task for PRT.04/SRV.01/CLI.02) and update this
note with confirmation before CQR.08 clears the blocking findings. Task status
remains `review`.

---

## PRT.04 [2026-07-09] — All findings addressed (except CQR.08-B-2, pending TASK-020)

Applied in `src/server/vw_server_core.c` and `src/client/vw_client_core.c`:

**SEC.07-B-1 (FIXED):** else-branch in `handle_auth_request` now always sends
`lockout_remaining_secs = 0`. Comment updated to explain the invariant.

**SEC.07-B-2 (FIXED):** `req.auth_token` and `req_buf` zeroed via `secure_zero` after
`vw_proto_send` and also on the encode-failure error path.

**SEC.07-B-3 (FIXED):** `if (req.username_len > VW_MAX_USERNAME_BYTES) return
VW_ERR_PROTO_INVALID;` added immediately after the decode call.

**SEC.07-A-1 (FIXED):** `handle_session_resume` validate-failure path normalized to
`VW_ERR_AUTH_BAD_CREDS`.

**SEC.07-A-2 (FIXED):** Both session-creation failure paths (`handle_auth_request` and
`handle_session_resume`) normalized to `VW_ERR_AUTH_BAD_CREDS`.

**SEC.07-A-3 (FIXED):** `secure_zero(&state, sizeof(state))` added in both the VW_OK
branch (before `vw_auth_create_session`) and the 2FA branch (after
`vw_auth_verify_2fa`).

**SEC.07-A-4 (FIXED):** `secure_zero(&ok, sizeof(ok))` and `secure_zero(buf/resp,
sizeof(...))` added in all AUTH_OK decode paths in `recv_auth_result` and the inline
handling in `vw_client_connect`.

**SEC.07-A-5 (FIXED):** `secure_zero(otp_buf, sizeof(otp_buf))` added after
`vw_proto_encode_auth_otp`.

**SEC.07-A-6 (PARTIAL):** TODO log comment added to revoke handler. Full warn-level
logging deferred until the logging subsystem is available.

**SEC.07-A-7 (DEFERRED):** Will be documented in `docs/PROTOCOL.md` threat model as
part of TASK-020.

**CQR.08-B-1 (FIXED):** Comments added to all four `(void)send_auth_fail` casts.

**CQR.08-B-2 (BLOCKED):** Cannot be resolved here — requires protocol extension.
TASK-020 created. `vw_client_user_id_of` declaration updated with a comment noting it
always returns 0 pending TASK-020.

**CQR.08-A-1 (FIXED):** `revoke_err` handler comment expanded with invariant rationale
and TODO log entry.

**CQR.08-A-2 (FIXED):** `#define AUTH_LOCKOUT_SECS 600u` added; both `600u` literals
replaced.

**CQR.08-A-3 (FIXED):** In-source comment added to `uid = state.user_id` line.

**CQR.08-A-4 (FIXED):** `quota_bytes`/`used_bytes` stubs updated with `TODO(SRV.01)`
reference.

**CQR.08-A-5 (N/A):** `#endif /* VW_SERVER_CORE_H */` guard already present in header.

**CQR.08-A-6 (N/A):** `auth_timeout_ms = 0` convention already documented in header.

**CQR.08-A-7 (CQR.08 action):** Awaiting CQR.08's STYLE.md update.

Requesting SEC.07 and CQR.08 re-review to confirm all blocking items resolved.
TASK-011 remains in `review` until CQR.08-B-2 is cleared via TASK-020.

---

SEC.07 [2026-07-10]: All three blocking findings (B-1, B-2, B-3) confirmed resolved.
Advisory findings A-1 through A-6 addressed satisfactorily; A-7 (AUTH_CHALLENGE 2FA
disclosure) is a design-level note documented in PROTOCOL.md §8.3.  No remaining
security concerns.  SEC.07 sign-off for TASK-011. ✓

CQR.08 [2026-07-10]: CQR.08-B-1 (missing comments on `(void)send_auth_fail` casts)
confirmed fixed.  CQR.08-B-2 (`vw_client_user_id_of` always returning 0) resolved via
TASK-020 (now `done`).  Advisory findings addressed.  No remaining blocking items.
CQR.08 sign-off for TASK-011. ✓

ARCH.00 [2026-07-10]: All reviewer sign-offs received.  TASK-020 is `done`.
TASK-011 milestone closed. ✓
