/*
 * vw_vault_kdf_wasm.c — TASK-141's in-browser Argon2id KEK derivation.
 *
 * Compiled to WASM via Emscripten (see build.sh) and linked against the
 * SAME pinned Argon2 reference implementation source used by the native
 * build (third_party/CMakeLists.txt, tag 20190702) — this file is not a
 * new crypto implementation, it's a thin wrapper mirroring
 * vw_crypto_vault_derive_kek (src/core/vw_crypto.c) exactly, so the
 * browser derives the identical KEK a native client would for the same
 * passphrase/salt/params. The constants below are intentionally
 * duplicated (not #included from vw_crypto.h, which pulls in mbedTLS
 * types this WASM module has no other use for) — keep them in sync with
 * src/core/vw_crypto.h's VW_VAULT_* definitions if either ever changes.
 *
 * AES-256-GCM (unwrapping the VK once the KEK is derived) deliberately
 * does NOT live here — the browser's native SubtleCrypto AES-GCM
 * implementation covers that per TASK-127's design decision, so this
 * module's only job is the one primitive the Web Crypto API doesn't
 * provide: Argon2id.
 *
 * Threading: compiled with ARGON2_NO_THREADS. The vault KDF pins
 * parallelism to 1 lane (VW_VAULT_ARGON2_PARALLELISM in vw_crypto.h), so
 * Argon2's reference core.c already runs strictly sequentially in that
 * configuration — ARGON2_NO_THREADS just removes the pthread dependency
 * entirely rather than linking a threading path that would never
 * actually run concurrently, which also sidesteps WASM threads'
 * SharedArrayBuffer/COOP-COEP requirements altogether.
 */

#include <stdint.h>
#include <emscripten/emscripten.h>
#include "argon2.h"

#define VW_VAULT_KDF_SALT_BYTES        16u
#define VW_VAULT_KEK_BYTES             32u
#define VW_VAULT_ARGON2_MIN_MEM_KB     19456u  /* 19 MiB floor */
#define VW_VAULT_ARGON2_MIN_TIME_COST  2u
#define VW_VAULT_ARGON2_PARALLELISM    1u

/*
 * Returns 0 on success, -1 if params fall below the pinned floor or use
 * the wrong parallelism (mirrors vw_crypto_vault_derive_kek's own
 * VW_ERR_INVALID_ARG cases — a corrupted/tampered kdf_params blob read
 * back from the server must never silently weaken the derivation here
 * either), -2 on an Argon2 library failure (OOM is the realistic case in
 * a browser tab given the multi-MiB memory cost).
 *
 * salt must point to exactly VW_VAULT_KDF_SALT_BYTES bytes; out_kek must
 * point to a caller-allocated VW_VAULT_KEK_BYTES-byte buffer. Both live in
 * WASM linear memory - the JS wrapper (vault-crypto.ts) is responsible
 * for writing/reading through Module.HEAPU8 at the pointers it allocated.
 */
EMSCRIPTEN_KEEPALIVE
int vw_wasm_derive_kek(const uint8_t *passphrase, uint32_t passphrase_len,
                        const uint8_t *salt,
                        uint32_t mem_cost_kib, uint32_t time_cost, uint32_t parallelism,
                        uint8_t *out_kek) {
    if (mem_cost_kib < VW_VAULT_ARGON2_MIN_MEM_KB) return -1;
    if (time_cost < VW_VAULT_ARGON2_MIN_TIME_COST) return -1;
    if (parallelism != VW_VAULT_ARGON2_PARALLELISM) return -1;

    int rc = argon2id_hash_raw(
        time_cost, mem_cost_kib, parallelism,
        passphrase, passphrase_len,
        salt, VW_VAULT_KDF_SALT_BYTES,
        out_kek, VW_VAULT_KEK_BYTES
    );

    return (rc == ARGON2_OK) ? 0 : -2;
}
