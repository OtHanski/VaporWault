---
id:          TASK-003
title:       Implement vw_crypto module
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-06-23
priority:    critical
depends_on:  [TASK-001]
blocks:      [TASK-008, TASK-009]
review_by:   [CQR.08, SEC.07]
tags:        [crypto, phase-0, security-sensitive]
---

Implement src/core/vw_crypto.{h,c}: all cryptographic primitives used project-wide.
This module wraps mbedTLS and the vendored Argon2id implementation.

## Acceptance criteria

- `vw_crypto_sha256(data, len, out_hash)` — SHA-256 via mbedTLS
- `vw_crypto_sha256_file(fd, out_hash)` — streaming SHA-256 over a file descriptor
- `vw_crypto_random(buf, len)` — cryptographically secure random bytes via mbedTLS CSPRNG
- `vw_crypto_argon2id(password, pw_len, salt, salt_len, out_hash, out_len, time_cost, mem_kb, parallelism)` — Argon2id via vendored ref impl
- `vw_crypto_argon2id_verify(hash, password, pw_len)` — constant-time verify
- `vw_crypto_totp_hotp(key, key_len, counter, out_code)` — HMAC-SHA1 HOTP for future TOTP 2FA
- `vw_crypto_constant_time_eq(a, b, len)` — timing-safe comparison
- All error paths return a vw_err_t; no silent failure
- _Static_assert verifies hash output sizes at compile time

## Notes

ARCH.00 [2026-06-23]: Default Argon2id parameters per OWASP 2023 recommendation:
time_cost=3, mem_kb=65536 (64 MB), parallelism=4. These should be defined as
compile-time constants with a note that admins running resource-constrained hardware
may reduce mem_kb. Benchmark in Phase 1 on target hardware.

SEC.07 review required before done — constant-time compare and Argon2id parameters
are security-critical.

PRT.04 [2026-06-23]: Implementation complete in src/core/vw_crypto.{h,c}.
- SHA-256: buffer via mbedtls_sha256(); file via streaming mbedtls_sha256_context
- CSPRNG: mbedtls_ctr_drbg seeded with "vapourwault_ctr_drbg_v1"
- Argon2id: calls argon2id_hash_raw() with OWASP 2023 params; generates random salt if NULL passed
- Constant-time compare: volatile pointer XOR accumulator loop
- HOTP: 8-byte big-endian counter → HMAC-SHA1 (mbedTLS) → RFC 4226 dynamic truncation → 6-digit mod 1000000
- TOTP verify: checks t±VW_TOTP_WINDOW using constant_time_eq
- Hex encode/decode: lowercase; decode validates every nibble
Awaiting CQR.08 and SEC.07 review.

CQR.08 [2026-06-23]: Three blocking findings. (1) vw_crypto_init leaks mbedTLS entropy and CSPRNG contexts when the seed step fails, because the cleanup guard on g_initialized means vw_crypto_cleanup() will not release them. Fix: call mbedtls_ctr_drbg_free and mbedtls_entropy_free before the early return. (2) vw_crypto_argon2id_verify leaves a 32-byte derived hash on the stack without zeroing; add memset before all return paths. (3) Including <windows.h> in the public vw_crypto.h header is forbidden — split the platform-specific SHA-256 file API or forward-declare HANDLE. Task cannot move to done until all three are resolved.
Findings:
[blocking] vw_crypto_init resource leak on seed failure: mbedtls_entropy_init and mbedtls_ctr_drbg_init are called before mbedtls_ctr_drbg_seed; if seed fails the function returns VW_ERR_CRYPTO without freeing either context, and vw_crypto_cleanup() will not free them because g_initialized stays 0.
[blocking] vw_crypto_argon2id_verify: the local stack buffer 'computed' (32 bytes of derived key material) is never zeroed before the function returns on either success or failure path; add memset(computed, 0, sizeof(computed)) before every return per style guide §6.
[blocking] vw_crypto.h includes <windows.h> inside the public header under #ifdef _WIN32, pulling the entire Win32 namespace into every translation unit on Windows; split the file-hashing API into a separate platform header or forward-declare HANDLE.
[advisory] vw_crypto_sha256_file: the local 'buf' is 65536 bytes (64 KiB) on the stack; consider making it static or reducing to 8192 bytes to avoid stack overflow on constrained platforms.
[advisory] Comments on lines 116 and 198 are what-comments that restate the code; remove or replace with why-comments per style guide §10.
[advisory] vw_crypto_hotp uses 'int i' as the loop variable iterating from 7 down to 0; add a brief comment noting why int is used rather than size_t to prevent future readers from flagging it.

SEC.07 [2026-06-23]: All Argon2id parameters and RFC 4226 HOTP encoding are correct. The sole blocking finding is the non-volatile accumulator in vw_crypto_constant_time_eq, which is the project's only constant-time primitive and is used for session token and hash comparison. Resolving that one issue makes TASK-003 approvable.
Findings:
[blocking] vw_crypto_constant_time_eq: the XOR accumulator 'diff' is declared as plain 'uint8_t', not 'volatile uint8_t'; an aggressive optimiser may legally eliminate the accumulation loop and short-circuit the comparison, defeating the constant-time guarantee. Fix: declare 'volatile uint8_t diff = 0;' at vw_crypto.c line 165.
[advisory] vw_crypto_argon2id_verify: the 'computed' buffer on the stack is not zeroed after use; add 'explicit_bzero(computed, sizeof(computed))' or equivalent before returning, guarded by a compiler-barrier macro.
[advisory] vw_crypto_hotp uses HMAC-SHA1 as required by RFC 4226; SHA-1 is broken for collision resistance but HOTP/TOTP only require second-preimage resistance on HMAC — acceptable for Phase 0 but evaluate migrating to HOTP-SHA256 in a later phase for defence-in-depth.

PRT.04 [2026-06-24]: All blocking findings resolved.
- CQR.08 #1 (init leak): added mbedtls_ctr_drbg_free + mbedtls_entropy_free before returning VW_ERR_CRYPTO on seed failure.
- CQR.08 #2 (computed not zeroed): restructured vw_crypto_argon2id_verify — now calls memset(computed, 0, sizeof(computed)) on both the error and success paths.
- CQR.08 #3 (<windows.h> in public header): removed entirely from vw_crypto.h; added platform-agnostic vw_file_handle_t typedef (void* on Win32, int on POSIX). <windows.h> moved inside #ifdef _WIN32 block in vw_crypto.c; POSIX prototype updated to use vw_file_handle_t.
- SEC.07 #1 (volatile accumulator): changed 'uint8_t diff = 0' to 'volatile uint8_t diff = 0' in vw_crypto_constant_time_eq.
Requesting CQR.08 and SEC.07 sign-off to move to done.

CQR.08 [2026-06-24]: All three blocking findings confirmed resolved. (1) vw_crypto_init now calls mbedtls_ctr_drbg_free then mbedtls_entropy_free before returning VW_ERR_CRYPTO on seed failure — no leak. (2) vw_crypto_argon2id_verify zeroes `computed` on both exit paths (Argon2 failure and match/mismatch). (3) vw_crypto.h carries no <windows.h> include; vw_file_handle_t is defined via a platform ifdef using void* vs int, with <windows.h> confined to the #ifdef _WIN32 block in the .c file. Advisory: the memset calls zeroing `computed` are technically eligible for dead-store elimination by an optimising compiler; replacing them with mbedtls_platform_zeroize (available in the already-vendored mbedTLS) would be more robust. No blocking regressions introduced. Task approved to proceed to done pending ARCH.00 confirmation.
[advisory] src/core/vw_crypto.c, vw_crypto_argon2id_verify, lines 160 and 165: memset used to zero the `computed` stack buffer before return. An optimising compiler may elide these as dead stores under the as-if rule. Replace both calls with mbedtls_platform_zeroize (already available via the vendored mbedTLS) to guarantee zeroing regardless of optimisation level.

SEC.07 [2026-06-24]: Both findings resolved. (1) vw_crypto_constant_time_eq: accumulator declared as `volatile uint8_t diff = 0` (line 174); input pointers also cast to `const volatile uint8_t *` — optimizer cannot collapse the loop. Blocking finding cleared. (2) vw_crypto_argon2id_verify: `computed` is zeroed via `memset` on every return path (error path line 160, comparison path line 165) — no key material left on the stack. Advisory/blocking finding cleared. No new findings.

ARCH.00 [2026-06-24]: All required reviewers have signed off with no blocking findings outstanding. Task marked done. The CQR.08 advisory (replace memset with mbedtls_platform_zeroize) is noted; a follow-up advisory task will be created for PRT.04 to apply the hardening across all zeroing sites in vw_crypto.c.
