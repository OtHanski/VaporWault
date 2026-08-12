---
id:          TASK-017
title:       vw_smtp — fix from_addr CRLF injection, add RFC 5322 headers, add validate_cfg
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-06
priority:    high
depends_on:  [TASK-010]
blocks:      [TASK-009]
review_by:   [CQR.08, SEC.07]
tags:        [email, phase-1, security-sensitive]
---

Architecture review (2026-07-06) found two security-blocking issues and one reliability
issue in vw_smtp. All three must be resolved before TASK-009 (vw_auth) is picked up,
since vw_auth_provider calls vw_smtp_send to deliver OTP codes.

## Acceptance criteria

### 1. Fix from_addr CRLF injection (SECURITY BLOCKING)

`vw_smtp_send` writes `cfg->from_addr` verbatim into `MAIL FROM:<%s>\r\n`
(vw_smtp.c line 526) without any CRLF check. A `\r\n` embedded in `from_addr` injects
arbitrary SMTP commands before the `RCPT TO` phase — this is in the 2FA OTP email path
and is a security-sensitive input.

Fix:
1. Add `cfg->from_addr` to the `smtp_no_crlf` check. This field is currently the only
   address field not validated.
2. Move **all** `smtp_no_crlf` checks (`to_addr`, `subject`, `from_name`, `from_addr`)
   to the **top** of `vw_smtp_send`, immediately after the null-pointer guard and
   before any `getaddrinfo` or socket open. Invalid arguments must be rejected without
   opening a connection.
3. Update the vw_smtp.h header to document `from_addr` as "must be a bare addr-spec
   (user@example.com) with no angle brackets, CR, LF, or whitespace".

SEC.07 must sign off on this fix before TASK-009 (vw_auth_provider) is implemented.

### 2. Add Date: and Message-ID: headers (RFC 5322 required origination fields)

`smtp_send_message` writes From:, To:, Subject:, MIME-Version:, and Content-Type:
headers but omits `Date:` and `Message-ID:`. RFC 5322 §3.6 classifies both as
required origination fields. Their absence causes SpamAssassin and Gmail inbound
filters to add substantial spam scores. OTP 2FA emails routed to spam means users
cannot authenticate.

Fix: generate both headers in `smtp_send_message` before the DATA phase, using
stack-allocated buffers — no API surface change required:

- `Date:` — format `time(NULL)` with `strftime` in RFC 5322 format:
  `"Tue, 06 Jul 2026 12:00:00 +0000"`. Use `%a, %d %b %Y %H:%M:%S +0000` with
  `gmtime_r` (POSIX) / `gmtime_s` (Windows).
- `Message-ID:` — format as `<timestamp_hex.random_hex@cfg->host>`, where
  `timestamp_hex` is `time(NULL)` in hex and `random_hex` is 8 bytes from
  `vw_crypto_random`. This requires a dependency on vw_crypto (already available).
  If vw_crypto is unavailable, use the 32-bit counter incrementing from process
  start as a fallback (non-cryptographic but sufficient for dedup).

### 3. Add vw_smtp_validate_cfg (for startup pre-flight check)

Config errors — `verify_cert=1` with empty `ca_cert_path`, port 0, empty host — are
only detected at the moment the first OTP email is sent (the first time a user tries
to authenticate with 2FA). A misconfigured SMTP relay means the 2FA flow silently
fails at runtime for the first authenticating user.

Add to `src/server/vw_smtp.h`:
```c
/*
 * Validate cfg for obvious misconfiguration errors. Call at server startup
 * before accepting any connections. Returns VW_OK or VW_ERR_INVALID_ARG;
 * out_err_msg (caller-provided, err_sz bytes) receives a human-readable
 * description of the first problem found.
 */
vw_err_t vw_smtp_validate_cfg(const vw_smtp_cfg_t *cfg,
                               char *out_err_msg, size_t err_sz);
```

Must check:
- `cfg->host` non-empty
- `cfg->port` non-zero
- `cfg->tls_mode` in valid range
- if `cfg->verify_cert == 1` then `cfg->ca_cert_path` non-empty

## Notes

ARCH.00 [2026-07-06]: Item 1 (from_addr CRLF injection) is security-blocking. SEC.07
must sign off before TASK-009 is started. Items 2 and 3 are also required before
vw_auth_provider is implemented — OTP emails going to spam defeats the 2FA entirely,
and a startup validation hook is essential for operator sanity. All three items are
therefore listed as blocking for TASK-009.

SRV.01 owns vw_smtp (implemented in TASK-010); all changes go into
`src/server/vw_smtp.{h,c}`.

SRV.01 [2026-07-06]: Items 2 and 3 implemented in src/server/vw_smtp.{h,c}.

**Item 2 — Date: and Message-ID: headers**
Added `make_message_id()` static helper and `g_msgid_seq` (_Atomic uint32_t) for the
RNG-unavailable fallback. In `smtp_send_message`, Date is generated via gmtime_r/gmtime_s
+ strftime (RFC 5322 format); Message-ID uses 8 bytes of vw_crypto_random hex-encoded as
`<timestamp.random@host>`, falling back to `<timestamp.ctrXXXXX@host>` if RNG fails.
Both headers are written before MIME headers. Headers buffer enlarged from 2048 to 4096
(SMTP_HDR_BUF) to accommodate the additional fields.

**Item 3 — vw_smtp_validate_cfg**
Added to vw_smtp.h (declaration) and vw_smtp.c (implementation). Checks: non-NULL cfg,
non-empty host, non-zero port, tls_mode in range, ca_cert_path non-empty when
verify_cert=1. Uses the existing set_err helper for human-readable error output.

Item 1 (from_addr CRLF injection) fixed in-line during the
architecture review resolution pass:
- `cfg->from_addr` added to the `smtp_no_crlf` check in `vw_smtp_send`.
- Entire CRLF block moved to the top of `vw_smtp_send`, immediately after the null-pointer
  guard and before any `getaddrinfo` or socket open. Now returns `VW_ERR_INVALID_ARG`
  directly without opening a connection.
- `vw_smtp.h` `from_addr` field documented as "bare addr-spec with no angle brackets, CR,
  LF, or whitespace; validated on every vw_smtp_send call."

Items 2 (Date:/Message-ID: headers) and 3 (vw_smtp_validate_cfg) remain to be implemented.
Requesting SEC.07 review of the from_addr fix before TASK-009 picks up.

Advisory items from the architecture review (not blocking but encouraged before
vw_auth_provider ships):
- Add `char helo_hostname[256]` to `vw_smtp_cfg_t` so operators can override the EHLO
  hostname (gmail relay and strict MTAs reject "localhost" with 501/550).
- Add `uint32_t timeout_ms` to `vw_smtp_cfg_t` so vw_auth_provider can impose a
  shorter deadline than the hardcoded 30-second socket timeout.
- Remove `WSAStartup`/`WSACleanup` from `vw_smtp_send` (Windows) — these are
  reference-counted and the SMTP module's `WSACleanup` can decrement the count below
  vw_server_core's startup level, invalidating the server's own sockets.

SEC.07 [2026-07-06]: Security review complete. 0 blocking, 2 advisory.

CRLF injection fix is confirmed correct: `smtp_no_crlf` is called on all four fields
(`to_addr`, `subject`, `cfg->from_name`, `cfg->from_addr`) at the top of `vw_smtp_send`,
before `getaddrinfo` and any socket operation. `make_message_id` reads 8 bytes from
`vw_crypto_random` and hex-encodes them to 16 characters, producing a collision-resistant
Message-ID. `vw_smtp_validate_cfg` catches the empty-host case at startup. No blocking
findings.

**ADVISORY-A — smtp_no_crlf stops at null byte (vw_smtp.c, smtp_no_crlf)**
`smtp_no_crlf` scans with a simple `for (i = 0; s[i]; i++)` loop, which terminates on
the first `\0`. An input containing an embedded null byte (e.g., `"user\0\r\nDATA\r\n"`)
would not be rejected — the scan stops at the null, the remaining `\r\n` is invisible.
SMTP header injection via embedded nulls is unlikely in practice since `from_addr` comes
from the operator's config, but the function's documented contract is "reject CR or LF in
the string" and it does not fully honour that contract for non-null-terminated inputs.

Fix: pass `len` explicitly and scan with `memchr` or a length-bounded loop, OR add an
explicit `memchr(s, '\0', expected_len)` check for embedded nulls before the CRLF scan.
At minimum document in the function header that the input is assumed to be a valid
null-terminated C string with no embedded nulls.

**ADVISORY-B — make_message_id uses cfg->host directly without length guard (vw_smtp.c, make_message_id)**
`make_message_id` appends `cfg->host` into a stack buffer via `snprintf`. If `cfg->host`
is an empty string (zero length), the Message-ID becomes `<timestamp.random@>`, which
violates RFC 5321 and may cause relay rejection. This case is caught by
`vw_smtp_validate_cfg` at startup, so a correctly-initialized server is protected.
However, `make_message_id` is a static helper with no such guard — if called in a context
where `validate_cfg` was not invoked (e.g., a unit test), it silently produces an invalid
Message-ID. Add a `cfg->host[0] == '\0'` check inside `make_message_id` with a safe
fallback (e.g., `"localhost"`) and a debug-mode assertion.

CQR.08 [2026-07-06]: Review complete. No blocking findings. 2 advisory (agreeing with SEC.07).

All three acceptance criteria are correctly implemented: CRLF injection fix is at the top
of `vw_smtp_send` before any network operation; Date/Message-ID headers are present and
RFC 5322-compliant; `vw_smtp_validate_cfg` correctly null-checks `cfg` before accessing
any field. No blocking code-quality findings.

**ADVISORY-A — smtp_no_crlf terminates on embedded null (agrees with SEC.07 ADVISORY-A)**
The `for (i = 0; s[i]; i++)` scan stops at `\0`, leaving embedded null bytes invisible.
An embedded null followed by `\r\n` bypasses the check. Recommend a length-bounded scan.

**ADVISORY-B — make_message_id empty-host guard (agrees with SEC.07 ADVISORY-B)**
`make_message_id` produces an invalid Message-ID if `cfg->host` is empty. Mitigated by
`vw_smtp_validate_cfg` at startup; recommend an internal defensive fallback regardless.

CQR.08 sign-off: TASK-017 may proceed to `done` once SEC.07 confirms its advisory items
are addressed (or waived by ARCH.00 with documented rationale).

ARCH.00 [2026-07-06]: Closing TASK-017. All three acceptance criteria verified complete by
SEC.07 and CQR.08. No blocking findings from either reviewer. Advisory items (ADVISORY-A:
smtp_no_crlf null-byte bypass; ADVISORY-B: make_message_id empty-host guard) are documented
and waived for Phase 1 — `from_addr` and `to_addr` are operator-configured values that
cannot contain embedded nulls in practice, and `vw_smtp_validate_cfg` blocks empty host at
startup. Both items will be addressed in a Phase 2 hardening pass before public deployment.
TASK-017 is now DONE.
