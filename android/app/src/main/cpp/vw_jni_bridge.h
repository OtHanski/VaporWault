#ifndef VW_JNI_BRIDGE_H
#define VW_JNI_BRIDGE_H

/*
 * vw_jni_bridge — JNI shim over vw_client_core (TASK-225/226). Vault RPCs
 * (vw_vault.c) are TASK-230's job, not this file's.
 *
 * Every exported function follows the standard JNI naming convention
 * (Java_<package>_<Class>_<method>) for the Kotlin object
 * com.vaporwault.client.VwNative — see VwNative.kt for the 1:1 Kotlin
 * mirror, and VwClient.kt for the ergonomic wrapper built on top of it
 * (matching the relationship src/gui/client/vw_gui_ipc.h's VwGuiIpc has to
 * vw_ipc.h on desktop).
 *
 * ── Conventions used throughout this bridge ─────────────────────────────
 *
 * - A native session handle is a `vw_client_sess_t*` cast to `jlong` (safe
 *   on both 32- and 64-bit ABIs via the `intptr_t` round trip — see
 *   nativeConnect's implementation comment).
 * - Failure sentinel, uniformly: 0/-1/null/false depending on return type
 *   (0 for a handle or id, since neither is ever legitimately 0; -1 for a
 *   count/prefs value; null for a fetched object/array; false only where
 *   there is no ambiguity with a real result). Every failure additionally
 *   sets the thread-local error slot — call nativeLastError() for the
 *   vw_err_t code.
 * - A "list" call (file/share/link/version) returns one `jbyteArray`:
 *   `u32 count` followed by `count` fixed-shape little-endian records, one
 *   per entry. Records are only ever emitted by this bridge (never parsed
 *   as input), so field order/widths just need to match VwClient.kt's
 *   decoder, documented per record type below and in that file. Uses the
 *   same `vw_write_u32le`/`vw_write_u64le`/`vw_proto_write_str`-style LE
 *   encoding docs/STYLE.md §14 already mandates for the wire protocol
 *   itself — no reliance on C struct memory layout/padding crossing the
 *   JNI boundary.
 * - Large chunk payloads (upload input, download output) cross as a
 *   Kotlin-owned `java.nio.DirectByteBuffer` via `GetDirectBufferAddress`,
 *   never a `jbyteArray` copy — see nativeChunkUploadIfMissing/
 *   nativeChunkDownloadRaw.
 */

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Session lifecycle ────────────────────────────────────────────────── */

/*
 * Connect to host:port and authenticate with username/password.
 *
 * ca_cert_pem_path: pass an empty string to use VW_CERT_VERIFY_NONE (test
 * only — see ARCHITECTURE.md's gateway precedent for why this must never be
 * the production default); a real path enables VW_CERT_VERIFY_REQUIRED.
 *
 * otp: pass an empty string on the first attempt. If the account has 2FA
 * enabled, this returns 0 with nativeLastError() == VW_ERR_AUTH_2FA_REQUIRED
 * (§8.3's challenge is never surfaced as a separate blocking call — the
 * caller re-invokes nativeConnect with the same host/username/password
 * plus the OTP code the user was prompted for, matching the existing
 * account_add()/vw_gui_ipc precedent: the OTP is collected up front, not
 * via a real async native-to-Java callback mid-handshake).
 *
 * Returns a non-zero native session handle on success, or 0 on failure —
 * call nativeLastError() to get the vw_err_t code. The caller (Kotlin) owns
 * the handle and must eventually pass it to nativeLogout().
 */
JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeConnect(
    JNIEnv *env, jobject thiz,
    jstring host, jint port, jstring ca_cert_pem_path,
    jstring username, jbyteArray password, jstring otp);

/*
 * Resume a saved session using a previously-stored token (PROTOCOL.md §7.1:
 * single-use — the server issues a fresh replacement token on success; the
 * caller must re-fetch and re-persist it via nativeGetToken() immediately
 * after). Returns a non-zero handle on success, 0 on failure.
 */
JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeSessionResume(
    JNIEnv *env, jobject thiz,
    jstring host, jint port, jstring ca_cert_pem_path,
    jbyteArray saved_token);

/* Copies the session's current token (32 bytes) — persist this after
 * connect/resume for a future nativeSessionResume() call. */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeGetToken(JNIEnv *env, jobject thiz,
                                                    jlong session_handle);

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeUserId(JNIEnv *env, jobject thiz,
                                                  jlong session_handle);

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeExpiresAt(JNIEnv *env, jobject thiz,
                                                     jlong session_handle);

JNIEXPORT jboolean JNICALL
Java_com_vaporwault_client_VwNative_nativeIsAdmin(JNIEnv *env, jobject thiz,
                                                   jlong session_handle);

/* Returns the vw_err_t code from the most recent bridge call on this
 * thread that failed (0 == VW_OK). */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeLastError(JNIEnv *env, jobject thiz);

/* Send AUTH_LOGOUT, close the TLS connection, and free the session. Safe
 * to call with a handle from a failed connect (0) — becomes a no-op. */
JNIEXPORT void JNICALL
Java_com_vaporwault_client_VwNative_nativeLogout(JNIEnv *env, jobject thiz,
                                                  jlong session_handle);

/* ── File operations ──────────────────────────────────────────────────── */

/*
 * FILE_LIST(_by_id). recursive enumerates subdirectories (server-side BFS,
 * capped at 65535 entries). Returns the record-array encoding documented
 * above (one record per vw_file_entry_t field — see VwClient.kt's
 * FileEntry/decodeFileEntries for the exact per-record layout), or null on
 * failure (VW_ERR_NOT_FOUND if the path/id doesn't exist).
 */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileList(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jstring virtual_path,
                                                    jboolean recursive);

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileListById(JNIEnv *env, jobject thiz,
                                                        jlong session_handle,
                                                        jlong dir_file_id,
                                                        jboolean recursive);

/* FILE_STAT(_by_id). Returns one file-entry record (no count prefix — the
 * caller already knows there's exactly one), or null on failure. */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileStat(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jstring virtual_path);

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileStatById(JNIEnv *env, jobject thiz,
                                                        jlong session_handle,
                                                        jlong file_id);

/* FILE_DELETE(_by_id). Returns the vw_err_t code (0 == success). */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeFileDelete(JNIEnv *env, jobject thiz,
                                                      jlong session_handle,
                                                      jstring virtual_path);

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeFileDeleteById(JNIEnv *env, jobject thiz,
                                                          jlong session_handle,
                                                          jlong file_id);

/* FILE_MOVE. new_parent_dir_id == 0 means "move to owner's own root";
 * new_name empty keeps the current name (move-only). Returns vw_err_t. */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeFileMove(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jlong file_id,
                                                    jlong new_parent_dir_id,
                                                    jstring new_name);

/* FILE_MKDIR. new_parent_dir_id == 0 means caller's own root. Returns the
 * new directory's file_id, or 0 on failure. */
JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeFileMkdir(JNIEnv *env, jobject thiz,
                                                     jlong session_handle,
                                                     jlong new_parent_dir_id,
                                                     jstring name);

/* ── Chunked transfer primitives (TASK-226 scope: the same "raw" primitives
 * vw_vault.c uses, not the local-path convenience wrappers — Android drives
 * its own chunk loop against a SAF/private-cache fd, and doing so this way
 * avoids needing a native-to-Java progress callback) ────────────────────── */

/*
 * CHUNK_QUERY+CHUNK_UPLOAD for one chunk (query, then upload only if the
 * server doesn't already have it — resumable-upload dedup, same as every
 * other chunk path in this protocol). `data` must be a direct ByteBuffer
 * (GetDirectBufferAddress) at least `len` bytes long, positioned at the
 * plaintext/ciphertext chunk bytes to send. Returns vw_err_t.
 */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeChunkUploadIfMissing(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jbyteArray hash, jobject data, jint len);

/*
 * FILE_COMMIT. One call covers all three FILE_COMMIT modes the server
 * dispatches on file_id/name_or_path together (see vw_client_core.c's
 * vw_client_file_commit_raw doc and its three callers):
 *   file_id == 0, name_or_path = full owned virtual_path  -> create at path
 *   file_id != 0 names an existing FILE, name_or_path empty -> new version
 *   file_id != 0 names a FOLDER the caller has EDIT on, name_or_path =
 *     bare leaf name                                        -> create inside it
 * chunk_hashes is chunk_count*32 bytes, concatenated, in upload order.
 * vault_id == 0 omits the vault trailing fields entirely (a plaintext
 * commit); nonzero requires a non-empty wrapped_dek (TASK-230 will be the
 * first real caller of the vault_id != 0 path from Android).
 * Returns {file_id, version_id} as a 2-element long[] on success, or null.
 */
JNIEXPORT jlongArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileCommit(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong file_id, jstring name_or_path,
    jlong logical_size, jbyteArray chunk_hashes,
    jlong vault_id, jbyteArray wrapped_dek);

/*
 * VERSION_CHUNKS. Returns one encoded result (u32 chunk_count, u64
 * vault_id, u16 wrapped_dek_len + wrapped_dek bytes, then
 * chunk_count*32 bytes of hashes — see VwClient.kt's decodeVersionChunks),
 * or null on failure.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionChunksRaw(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong version_id);

/*
 * CHUNK_DOWNLOAD_REQ/CHUNK_DATA for one chunk by content hash, verified
 * against `hash` before returning. `out` must be a direct ByteBuffer at
 * least `out_capacity` bytes; the received bytes are written starting at
 * its position 0. Returns the actual byte count written, or -1 on failure
 * (including VW_ERR_PROTO_INVALID if the received bytes don't hash to
 * `hash`, or if the chunk is larger than out_capacity).
 */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeChunkDownloadRaw(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jbyteArray hash, jobject out, jint out_capacity);

/* ── Version history ──────────────────────────────────────────────────── */

/* VERSION_LIST(_by_id), oldest first. Record-array encoding (see
 * VwClient.kt's VersionEntry/decodeVersionEntries), or null on failure. */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionList(JNIEnv *env, jobject thiz,
                                                       jlong session_handle,
                                                       jstring virtual_path);

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionListById(JNIEnv *env, jobject thiz,
                                                           jlong session_handle,
                                                           jlong file_id);

/* VERSION_RESTORE(_by_id). Returns vw_err_t. */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionRestore(JNIEnv *env, jobject thiz,
                                                          jlong session_handle,
                                                          jstring virtual_path,
                                                          jlong version_id);

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionRestoreById(JNIEnv *env, jobject thiz,
                                                              jlong session_handle,
                                                              jlong version_id);

/* ── Sharing ───────────────────────────────────────────────────────────── */

/* SHARE_GRANT. permission is a vw_perm_t (0=none,1=view,2=edit,3=owner);
 * expires_at == 0 means never. Returns the new share_id, or 0 on failure. */
JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeShareGrant(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong file_id, jstring target_username,
    jint permission, jlong expires_at);

/* SHARE_REVOKE. Returns vw_err_t. */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeShareRevoke(JNIEnv *env, jobject thiz,
                                                       jlong session_handle,
                                                       jlong share_id);

/* SHARE_LIST. mode: 0 = grants I created, 1 = grants granted to me.
 * Record-array encoding (see VwClient.kt's ShareEntry), or null. */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeShareList(JNIEnv *env, jobject thiz,
                                                     jlong session_handle,
                                                     jint mode);

/*
 * LINK_CREATE. password may be empty for none. Returns a fixed 40-byte
 * result (8 bytes share_id + 32 bytes raw link token — the only time the
 * token is ever available, per vw_client_link_create's doc; never
 * persisted by this bridge, and the caller must not re-fetch it later
 * either, since the server never re-discloses it), or null on failure.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeLinkCreate(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong file_id, jint permission,
    jlong expires_at, jstring password);

/* LINK_REVOKE. Returns vw_err_t. */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeLinkRevoke(JNIEnv *env, jobject thiz,
                                                      jlong session_handle,
                                                      jlong share_id);

/* LINK_LIST. file_id_filter == 0 lists all of them. Record-array encoding
 * (see VwClient.kt's LinkEntry), or null. Never includes the raw token. */
JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeLinkList(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jlong file_id_filter);

/* ── Account self-service ──────────────────────────────────────────────── */

/* ACCOUNT_EMAIL_GET. Returns the address ("" = none on file), or null on
 * failure — distinct from "", which is itself a valid, successful result. */
JNIEXPORT jstring JNICALL
Java_com_vaporwault_client_VwNative_nativeAccountEmailGet(JNIEnv *env, jobject thiz,
                                                           jlong session_handle);

/* ACCOUNT_EMAIL_SET. email == "" clears it. Returns the stored value on
 * success (echoed by the server), or null on failure (e.g.
 * VW_ERR_INVALID_ARG for a malformed address, VW_ERR_ALREADY_EXISTS if
 * another account owns it already). */
JNIEXPORT jstring JNICALL
Java_com_vaporwault_client_VwNative_nativeAccountEmailSet(JNIEnv *env, jobject thiz,
                                                           jlong session_handle,
                                                           jstring email);

/* ACCOUNT_2FA_GET. Returns 0 (disabled), 1 (enabled), or -1 on failure. */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeAccount2faGet(JNIEnv *env, jobject thiz,
                                                         jlong session_handle);

/*
 * ACCOUNT_2FA_SET. Requires re-proving the current password (a
 * security-sensitive toggle, not a preference — see vw_client_core.h's
 * doc). Returns the stored value after the call (0/1), or -1 on failure
 * (VW_ERR_AUTH_BAD_CREDS for a wrong password; VW_ERR_INVALID_ARG when
 * enabling with no email on file — nativeAccountEmailSet first).
 */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeAccount2faSet(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jbyteArray password, jboolean enable);

/* NOTIFY_PREFS_GET. Returns the VW_NOTIFY_* bitmask as a non-negative
 * long, or -1 on failure. */
JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeNotifyPrefsGet(JNIEnv *env, jobject thiz,
                                                          jlong session_handle);

/*
 * NOTIFY_PREFS_SET. Replaces the COMPLETE bitmask, not a per-bit toggle —
 * callers should nativeNotifyPrefsGet() first, flip the bit locally, and
 * pass the full result here. Returns the stored value after the call, or
 * -1 on failure (VW_ERR_INVALID_ARG for a reserved bit outside
 * VW_NOTIFY_ALL_KNOWN).
 */
JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeNotifyPrefsSet(JNIEnv *env, jobject thiz,
                                                          jlong session_handle,
                                                          jlong prefs);

#ifdef __cplusplus
}
#endif

#endif /* VW_JNI_BRIDGE_H */
