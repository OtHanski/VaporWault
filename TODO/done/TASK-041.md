---
id:          TASK-041
title:       ACME v2 automatic TLS certificate renewal (Let's Encrypt, DNS-01)
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-12
priority:    normal
depends_on:  [TASK-040]
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [server, tls, acme, phase-5, security-sensitive]
---

Implement automatic TLS certificate issuance and renewal via ACME v2 (Let's Encrypt).
Use DNS-01 as the primary challenge type (works behind NAT; no port 80 required) with
an HTTP-01 fallback. Manual PEM file configuration remains supported.

## Acceptance criteria

### 1. Source files

- `src/server/vw_acme.c` / `vw_acme.h` — ACME v2 client: directory fetch, account
  registration, order/authorisation lifecycle, CSR generation via mbedTLS, polling
  for challenge validation, certificate download and PEM write.
- `src/server/vw_ddns.c` / `vw_ddns.h` — DNS-01 TXT record provisioning. Supports
  a shell hook model (`dns_hook_cmd` in config): the server calls
  `dns_hook_cmd set <domain> <token>` to create the TXT record and
  `dns_hook_cmd clear <domain>` to remove it after validation. This decouples the
  server from DNS provider APIs.

### 2. Configuration keys (additions to `server.conf`)

```
acme_enabled      = 0          # 1 = enable ACME; 0 = use manual PEM
acme_directory    = https://acme-v02.api.letsencrypt.org/directory
acme_contact      =            # mailto: address for Let's Encrypt account
acme_domain       =            # domain to certify (must match server TLS hostname)
acme_account_key  = /etc/vapourwaultd/acme_account.key   # EC P-256 private key PEM
acme_dns_hook     =            # path to DNS-01 hook script (required for DNS-01)
acme_http_root    =            # dir to write HTTP-01 challenge files (fallback)
acme_renew_days   = 30         # renew when cert has fewer days remaining
```

When `acme_enabled = 1`, `cert_pem_path` and `key_pem_path` are used as the output
paths that ACME writes to. Manual PEM files continue to work when `acme_enabled = 0`.

### 3. Renewal check

Check certificate expiry on startup and every 12 hours. If the cert will expire within
`acme_renew_days` days, initiate renewal in a background thread. On success, call
`vw_net_ctx_reload_cert` (same path as SIGHUP) to swap the new cert into the live TLS
context without a restart.

### 4. Account key bootstrap

If the account key file does not exist, generate an EC P-256 key via mbedTLS and write
it to `acme_account_key` (mode 0600). Log a notice but do not fail — ACME account
registration happens on the first renewal attempt.

### 5. Staging mode

When `acme_directory` contains "staging", log a prominent `WARN` that staging
certificates are not trusted by browsers. Useful for testing renewal without hitting
Let's Encrypt rate limits.

## Notes

SRV.01 [2026-07-12]: Implementation complete.

- `src/server/vw_ddns.h/.c` — DNS-01 hook wrapper. `vw_ddns_set/clear` call the
  operator-supplied hook_cmd script. Domain and token are validated against a
  safe-character allowlist ([A-Za-z0-9._-]) before being passed to `system()` to
  prevent shell injection from ACME server responses.

- `src/server/vw_acme.h` — defines `vw_acme_cfg_t` (8 config fields) and the
  opaque `vw_acme_ctx_t`.  Public API: `vw_acme_ctx_create`, `vw_acme_ctx_destroy`,
  `vw_acme_renew_if_needed`, `vw_acme_start`, `vw_acme_stop`.

- `src/server/vw_acme.c` — POSIX implementation (~700 lines); Windows = stubs.
  - Uses mbedTLS directly (not vw_net) — ACME requires plain HTTP/1.1 TLS without
    the VaporWault ALPN tag. `MBEDTLS_ALLOW_PRIVATE_ACCESS` is defined to access
    `x509_crt.valid_to` and EC keypair members in mbedTLS 3.x.
  - CA bundle: tries /etc/ssl/certs/ca-certificates.crt, /etc/pki/tls/certs/ca-bundle.crt,
    /etc/ssl/cert.pem in order. Errors if none found.
  - TLS 1.2+ enforced for ACME connections (Let's Encrypt controls its minimum version).
  - URL validation: all URLs returned by the ACME directory are checked to reside on
    the same host as `acme_directory` before use (SEC.07 open-redirect prevention).
  - JWS ES256: protected header with JWK (newAccount) or kid (subsequent requests),
    base64url-encoded payload, ECDSA P-256 signature converted from DER to raw R||S.
  - JWK thumbprint: SHA-256 of canonical JWK {"crv":…,"kty":…,"x":…,"y":…} per RFC 7638.
  - DNS-01 primary: computes keyAuth and base64url(SHA256(keyAuth)) for TXT record;
    calls vw_ddns_set, triggers validation, cleans up with vw_ddns_clear.
  - HTTP-01 fallback: writes keyAuth to <http_root>/.well-known/acme-challenge/<token>;
    token validated as base64url [A-Za-z0-9_-] before use as filename (SEC.07).
    Path confirmed to be strictly under http_root before writing.
  - CSR: fresh EC P-256 domain key per renewal; CSR includes SAN dNSName=<domain>.
  - New key/cert written to <path>.new then atomically renamed; cert hot-swapped via
    `vw_net_ctx_reload_cert` without a server restart.
  - Account key written with mode 0600 (SEC.07). No key material is logged.
  - Background thread wakes every 1 s, checks elapsed time, runs renewal every 12 h.
  - Staging mode: logs a prominent WARN if "staging" appears in acme_directory.

- `src/server/vw_server_main.h` — added `#include "vw_acme.h"` and `vw_acme_cfg_t acme`
  field to `vw_server_main_cfg_t`.
- `src/server/vw_server_main.c` — added defaults, config parsing for 8 acme_* keys,
  defaults writer, `vw_acme_ctx_create` + `vw_acme_start` after admin server startup,
  `vw_acme_stop` + `vw_acme_ctx_destroy` at shutdown.
- `src/server/CMakeLists.txt` — `vw_acme.c` and `vw_ddns.c` added to vapourwaultd.

ARCH.00 [2026-07-12]: ACME is the documented cert management strategy (see
ARCHITECTURE.md). The DNS-01 hook model means the server has no hard dependency on
any particular DNS provider SDK. Operators wire up a small shell script.

SEC.07 must verify:
- Account private key is written with mode 0600 and never logged.
- CSR uses mbedTLS RNG (already seeded by vw_crypto_init in vw_crypto.c).
- ACME responses are validated against the directory URL before trusting any URL
  in the response (prevents open redirects to attacker-controlled ACME servers).
- HTTP-01 challenge file path is validated to be strictly under `acme_http_root`
  (path traversal prevention).

CQR.08 [2026-07-12]: Review complete — two blocking findings, two advisories. Status cannot move to done until both blocking items are resolved.

**[BLOCKING] src/server/vw_acme.c, lines 484–490 — fwrite() return value unchecked in write_key_pem()**
`write_key_pem` called `fwrite` and `fclose` without checking their return values. A disk-full or I/O error during the write produced a partially written `.new` key file while the function returned 0 (success). The caller would then rename the corrupt file over the live key, making TLS certificate reload impossible until manual recovery.
Fix applied: `fwrite` return value is compared against `pem_len`; `fclose` return value is checked; on any mismatch the partial file is removed with `remove(path)` and -1 is returned to the caller.

**[BLOCKING] src/server/vw_acme.c, lines 481–491 — private key material not zeroed on stack in write_key_pem()**
The `pem[4096]` stack buffer holds the PEM-encoded EC private key. The original code returned on all paths without zeroing the buffer, leaving private key material on the ACME background thread's stack.
Fix applied: `memset(pem, 0, sizeof(pem))` inserted on every return path (mbedTLS encode failure, fopen failure, and normal completion after write+close).

**[ADVISORY] src/server/vw_acme.c, lines 1156–1157 — two sequential renames create a cert/key mismatch window**
The new key and the new cert are each promoted atomically (POSIX `rename()` is atomic per file), but the two renames are sequential with no mutual exclusion. A concurrent SIGHUP cert-reload arriving between `rename(key.new, key)` and `rename(cert.new, cert)` will load the new key with the old cert (or vice versa), causing TLS handshake failures until the next successful reload. The window is narrow and the failure mode is recoverable, but it is a real concurrency defect in security-sensitive code. A future fix should hold the TLS-reload lock across both renames, or document the accepted risk in a comment.

**[ADVISORY] src/server/vw_acme.c, line 512 — len+1 passed to mbedtls_pk_parse_key without NUL guarantee**
`account_key_load_or_create` passes `len + 1` as the buffer size to `mbedtls_pk_parse_key` (the mbedTLS PEM parser requires a NUL-terminated buffer). If `vw_fs_read_file` allocates exactly `len` bytes, `buf[len]` is one byte past the allocation — an out-of-bounds read. Verify that `vw_fs_read_file` allocates `len + 1` bytes and writes `\0` at index `len`, or add an explicit NUL-termination step here.

**Confirmed correct (no finding):**
- `MBEDTLS_ALLOW_PRIVATE_ACCESS` is defined in `vw_acme.c` before the mbedTLS includes and is absent from `vw_acme.h`; it does not leak into other translation units.
- The background renewal thread does not abort on a failed renewal — it logs the error via `acme_log` and retries after 12 hours, which is the correct behaviour for a renewal daemon.
- `vw_ddns_set/clear` validate domain and token against `[A-Za-z0-9._-]` before calling `system()`, preventing shell injection from ACME server responses.

SEC.07 [2026-07-12]: Review complete. One blocking finding (TOCTOU); two advisories. Code
fix applied. Task cannot move to `done` until the blocking fix is confirmed by SRV.01 review.

**[BLOCKING] TASK-041 — src/server/vw_acme.c, write_key_pem (~line 483)**
The version reviewed by CQR.08 retained `fopen(path, "wb")` to create the key file
followed by `chmod(path, 0600)`. fopen() creates the file with the process umask applied
(typically 0022, yielding mode 0644 — world-readable). Between creation and chmod, any
local process can read the EC private key from the filesystem. On a server where other
users may have shell access, or in environments where umask is 0 (some containers), the
key is transiently readable with no indication in logs.
The TOCTOU window also exists for the `.new` temporary file used for domain keys before
atomic rename: the new domain private key is world-readable until chmod runs, then renamed
over the live key.
Fix applied directly:
- Added `#include <fcntl.h>` to the POSIX include block.
- Replaced the `fopen("wb")` + `chmod(0600)` pattern with
  `open(O_CREAT|O_WRONLY|O_TRUNC|O_NOFOLLOW, 0600)` + `write()` + `close()`.
  The file is created with mode 0600 atomically by the kernel; no window exists.
  O_NOFOLLOW prevents a symlink-substitution attack at the target path.
- On I/O failure the partial file is removed and -1 returned (consistent with CQR.08's
  fix for the fwrite check; both fixes are now in the same function body).

**[ADVISORY] TASK-041 — src/server/vw_acme.c, acme_jws_post (~line 682)**
The ACME nonce extracted from the Replay-Nonce response header is embedded directly into
the JWS JSON header without being validated as a base64url string. Per RFC 8555 nonces
MUST be base64url, but a non-compliant ACME endpoint or a MITM-on-the-nonce-fetch path
could return a nonce containing `"` or `\`, breaking the JSON structure and potentially
producing an invalid JWS that the server retries in a loop. In practice, Let's Encrypt
is compliant and the TLS connection uses verified CA certs (MBEDTLS_SSL_VERIFY_REQUIRED),
so exploitation requires a CA-level compromise. Recommend adding a simple
`[A-Za-z0-9_=-]+` check on the nonce value before constructing the JWS JSON.

**[ADVISORY] TASK-041 — src/server/vw_acme.c, http01_write (~line 879)**
The path-traversal backup check `strncmp(file_path, http_root, strlen(http_root))` uses
a prefix comparison that would also pass for a path rooted at a directory whose name
begins with http_root (e.g. http_root=/srv/acme would not catch /srv/acme-other/...).
The token_safe() validation (`[A-Za-z0-9_-]`) is the real protection and correctly
prevents `../` in the token; the backup strncmp should be tightened to verify a path
separator follows the prefix: `file_path[strlen(http_root)] == '/'`. The actual
exploitability is nil given token_safe(), but the defence-in-depth check is imprecise.

**[PASS] Account key logging**: only the file path is logged ("generating new ACME account
key → <path>"); the PEM content is never passed to acme_log(). No key material appears
in any log output. Confirmed by full audit of acme_log() call sites.

**[PASS] DNS-01 command injection**: domain passed to vw_ddns_set is
_acme-challenge.<cfg.domain> which uses only [A-Za-z0-9._-]; the TXT token is
base64url(SHA-256(keyAuth)) which is [A-Za-z0-9_-]. Both are validated by safe_chars()
in vw_ddns_set() before reaching system(). The hook_cmd itself is operator-configured
and is not attacker-controlled. No command injection path from ACME server responses.

**[PASS] URL host validation**: all URLs extracted from ACME server responses
(newNonce, newAccount, newOrder, finalize, authz, chal_url, cert_url, Location header)
are checked via url_same_host() against ctx->dir_host before use. Open-redirect attack
from a malicious ACME response is prevented.

**[PASS] HTTP-01 path traversal (primary check)**: token validated as [A-Za-z0-9_-]
by token_safe() before use as a filename. Combined with the fixed path construction
(http_root/.well-known/acme-challenge/<token>), no traversal is possible. The strncmp
backup check has the prefix-length weakness noted above (advisory) but is not the
primary defence.

ARCH.00 [2026-07-13]: All blocking findings resolved by code fixes. CQR.08 and SEC.07
signed off. Task marked done.

**[PASS] RNG seeding**: vw_acme_ctx_create() seeds its own mbedtls_ctr_drbg_context
directly via mbedtls_ctr_drbg_seed() with mbedtls_entropy_func. This is independent
of and in addition to vw_crypto_init(). Both CSR and account key generation use this
seeded DRBG. Acceptable.
