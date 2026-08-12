/*
 * vault-crypto.ts — TASK-141's in-browser half of the vault's zero-
 * knowledge design. Everything here runs client-side only; the gateway
 * (TASK-135) only ever sees opaque wrapped-key blobs and ciphertext.
 *
 * Every primitive below was cross-verified byte-for-byte against the
 * native implementation (src/core/vw_crypto.c, src/client/vw_vault.c)
 * during development — not assumed compatible just because both sides
 * claim to implement a named standard:
 *   - Argon2id (via the WASM module) against vw_crypto_vault_derive_kek.
 *   - HKDF-SHA256 chunk nonce derivation against mbedtls_hkdf.
 *   - AES-256-GCM wrap/unwrap blob layout against mbedtls_gcm.
 * A nonce-derivation or wrap-format mismatch here would be a correctness
 * bug at best and a GCM nonce-reuse vulnerability at worst (TASK-141's
 * own acceptance criteria) — this is why the cross-check mattered more
 * than for most other code in this project.
 */

import createVaultKdfModule from "../wasm/dist/vw_vault_kdf.js";

export interface VaultKdfParams {
  memCostKib: number;
  timeCost: number;
  parallelism: number;
}

const VAULT_KEK_BYTES = 32;
const VAULT_KDF_SALT_BYTES = 16;
const AES_GCM_KEY_BYTES = 32;
const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const WRAPPED_KEY_BYTES = AES_GCM_NONCE_BYTES + AES_GCM_KEY_BYTES + AES_GCM_TAG_BYTES; // 60

/*
 * TypeScript 5.7+'s stricter typed-array generics (Uint8Array<ArrayBufferLike>,
 * e.g. from .slice()) don't structurally satisfy Web Crypto's BufferSource
 * parameter types even though every Uint8Array in this module is always
 * plain ArrayBuffer-backed (never SharedArrayBuffer) - this cast reflects
 * that guarantee rather than working around a real runtime risk.
 */
function asBufferSource(u8: Uint8Array): BufferSource {
  return u8 as unknown as BufferSource;
}

type VaultKdfModule = Awaited<ReturnType<typeof createVaultKdfModule>>;

let kdfModulePromise: Promise<VaultKdfModule> | null = null;
function getKdfModule(): Promise<VaultKdfModule> {
  if (kdfModulePromise === null) {
    kdfModulePromise = createVaultKdfModule();
  }
  return kdfModulePromise;
}

/*
 * Derive a vault KEK from a passphrase (Argon2id, matching
 * vw_crypto_vault_derive_kek exactly — same WASM-compiled Argon2 source
 * the native build vendors, TASK-141's own design decision to avoid a
 * second implementation drifting from the first). Rejects params below
 * the project's pinned floor, same as the native function.
 */
export async function deriveKek(
  passphrase: string,
  salt: Uint8Array,
  params: VaultKdfParams,
): Promise<Uint8Array> {
  if (salt.length !== VAULT_KDF_SALT_BYTES) {
    throw new Error(`salt must be ${VAULT_KDF_SALT_BYTES} bytes`);
  }
  const Module = await getKdfModule();
  const passphraseBytes = new TextEncoder().encode(passphrase);

  const passphrasePtr = Module._malloc(Math.max(passphraseBytes.length, 1));
  const saltPtr = Module._malloc(salt.length);
  const outPtr = Module._malloc(VAULT_KEK_BYTES);
  try {
    Module.HEAPU8.set(passphraseBytes, passphrasePtr);
    Module.HEAPU8.set(salt, saltPtr);

    const rc = Module.ccall(
      "vw_wasm_derive_kek",
      "number",
      ["number", "number", "number", "number", "number", "number", "number"],
      [
        passphrasePtr,
        passphraseBytes.length,
        saltPtr,
        params.memCostKib,
        params.timeCost,
        params.parallelism,
        outPtr,
      ],
    );
    if (rc !== 0) {
      throw new Error(
        rc === -1 ? "KDF parameters are below the required minimum" : "Argon2id derivation failed",
      );
    }
    return Module.HEAPU8.slice(outPtr, outPtr + VAULT_KEK_BYTES) as Uint8Array;
  } finally {
    // Zero the WASM-side passphrase copy before freeing it. The JS-side
    // passphraseBytes/passphrase string itself cannot be zeroed (a
    // fundamental JS limitation, not something this function can fix) -
    // this only closes the WASM-heap half of the exposure window.
    Module.HEAPU8.fill(0, passphrasePtr, passphrasePtr + passphraseBytes.length);
    Module._free(passphrasePtr);
    Module._free(saltPtr);
    Module._free(outPtr);
  }
}

async function importAesGcmKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", asBufferSource(rawKey), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/*
 * Wraps keyToWrap under wrappingKey, producing vw_vault.c's exact blob
 * layout: nonce[12] || ciphertext[32] || tag[16] (60 bytes) - Web
 * Crypto's AES-GCM concatenates ciphertext+tag on encrypt, which is
 * already this layout's second half.
 */
export async function wrapKey(wrappingKey: Uint8Array, keyToWrap: Uint8Array): Promise<Uint8Array> {
  const key = await importAesGcmKey(wrappingKey);
  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
  const ctWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: asBufferSource(nonce), tagLength: 128 },
      key,
      asBufferSource(keyToWrap),
    ),
  );
  const blob = new Uint8Array(WRAPPED_KEY_BYTES);
  blob.set(nonce, 0);
  blob.set(ctWithTag, AES_GCM_NONCE_BYTES);
  return blob;
}

/*
 * Unwraps a vw_vault.c-formatted blob. Throws on a GCM authentication
 * failure — indistinguishable here between "wrong passphrase" (VK
 * unwrap) and "corrupted blob," matching vw_crypto_aes256gcm_decrypt's
 * own documented ambiguity; callers add that semantic meaning.
 */
export async function unwrapKey(wrappingKey: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length !== WRAPPED_KEY_BYTES) {
    throw new Error("malformed wrapped-key blob");
  }
  const key = await importAesGcmKey(wrappingKey);
  const nonce = blob.slice(0, AES_GCM_NONCE_BYTES);
  const ctWithTag = blob.slice(AES_GCM_NONCE_BYTES);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: asBufferSource(nonce), tagLength: 128 },
      key,
      asBufferSource(ctWithTag),
    );
    return new Uint8Array(pt);
  } catch {
    throw new Error("wrong passphrase or corrupted key");
  }
}

/*
 * Deterministic per-chunk nonce (docs/PROTOCOL.md §7.11.3):
 * HKDF-SHA256(salt=empty, ikm=dek, info="vw-chunk-nonce" || chunk_index
 * as 8-byte LE)[0:12] — cross-verified against mbedtls_hkdf byte-for-byte
 * during development (see this file's header comment).
 */
async function chunkNonce(dek: Uint8Array, chunkIndex: number): Promise<Uint8Array> {
  const label = new TextEncoder().encode("vw-chunk-nonce");
  const info = new Uint8Array(label.length + 8);
  info.set(label, 0);
  new DataView(info.buffer, label.length, 8).setBigUint64(0, BigInt(chunkIndex), true);

  const hkdfKey = await crypto.subtle.importKey("raw", asBufferSource(dek), "HKDF", false, [
    "deriveBits",
  ]);
  const okm = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: asBufferSource(new Uint8Array(0)), info: asBufferSource(info) },
    hkdfKey,
    256,
  );
  return new Uint8Array(okm).slice(0, AES_GCM_NONCE_BYTES);
}

/* Encrypts one plaintext chunk under dek, using chunkIndex's deterministic
 * nonce. Returns ciphertext||tag concatenated (the exact bytes uploaded
 * as this chunk's content — matches vw_vault_upload_file's ct_buf). */
export async function encryptChunk(
  dek: Uint8Array,
  chunkIndex: number,
  plaintext: ArrayBuffer,
): Promise<ArrayBuffer> {
  const nonce = await chunkNonce(dek, chunkIndex);
  const key = await importAesGcmKey(dek);
  return crypto.subtle.encrypt({ name: "AES-GCM", iv: asBufferSource(nonce), tagLength: 128 }, key, plaintext);
}

/* Decrypts one downloaded chunk (ciphertext||tag) under dek/chunkIndex.
 * Throws on GCM auth failure (tampered/corrupted chunk). */
export async function decryptChunk(
  dek: Uint8Array,
  chunkIndex: number,
  ciphertextWithTag: ArrayBuffer,
): Promise<ArrayBuffer> {
  const nonce = await chunkNonce(dek, chunkIndex);
  const key = await importAesGcmKey(dek);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: asBufferSource(nonce), tagLength: 128 }, key, ciphertextWithTag);
}

export function randomDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(AES_GCM_KEY_BYTES));
}

export function randomSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(VAULT_KDF_SALT_BYTES));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
