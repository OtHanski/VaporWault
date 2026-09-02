#include "vw_jni_bridge.h"

#include "vw_client_core.h"
#include "vw_vault.h"
#include "../core/vw_crypto.h"
#include "../core/vw_net.h"
#include "../core/vw_proto.h"

#include <android/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "vw_jni_bridge"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Per-thread last-error slot (see vw_jni_bridge.h's header comment for the
 * failure-sentinel convention every function below follows).
 */
static _Thread_local vw_err_t g_last_error = VW_OK;

/*
 * vw_crypto_init() (PSA Crypto + the process-wide CTR-DRBG behind
 * vw_crypto_random) is required before anything in this bridge calls
 * vw_crypto_random — directly, or transitively via vw_vault_setup/_unlock
 * (fresh VK/salt generation, AES-GCM nonces) or vw_crypto_vault_derive_kek's
 * Argon2id path. Desktop's daemon calls this once at process startup
 * (vw_daemon.c, TASK-100's finding: login alone never needed it, only
 * vault operations do, so the gap was invisible until vaults existed).
 * Android has no daemon process for that call to live in — JNI_OnLoad is
 * the equivalent "once per process lifetime, before any other native
 * method can run" hook the JVM guarantees, so it belongs here instead.
 * Without it, every vault operation fails fast with VW_ERR_CRYPTO
 * (vw_crypto.c's g_initialized guard) while plaintext operations keep
 * working fine (TLS/session token generation don't go through this gate) —
 * exactly the confusing, vault-only failure mode this was found by.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    if (vw_crypto_init() != VW_OK) {
        LOGE("vw_crypto_init failed at library load");
        return -1;
    }
    return JNI_VERSION_1_6;
}

/* ── JNI string helpers ───────────────────────────────────────────────────
 * Returns NULL if `s` is a Java null OR GetStringUTFChars failed (OOM) —
 * every call site below checks for NULL rather than assuming success.
 * release_str() is a no-op if either argument is NULL, so it's always
 * safe to call unconditionally with whatever borrow_str() returned. */
static const char *borrow_str(JNIEnv *env, jstring s) {
    return s ? (*env)->GetStringUTFChars(env, s, NULL) : NULL;
}
static void release_str(JNIEnv *env, jstring s, const char *c) {
    if (s && c) (*env)->ReleaseStringUTFChars(env, s, c);
}

static jbyteArray make_byte_array(JNIEnv *env, const uint8_t *buf, uint32_t len) {
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
    if (arr) (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte *)buf);
    return arr;
}

/* ── Record-array encoding (see vw_jni_bridge.h's header comment) ────────
 * One pair of functions per entry type: <type>_encoded_size() (variable
 * only where a name/username field is involved) and write_<type>() (append
 * one record at *p, return the advanced pointer), plus an encode_<type>s()
 * that sizes+allocates+writes the u32-count-prefixed array and wraps it as
 * a jbyteArray. Kotlin's mirror-image decoder lives in VwClient.kt. */

static uint32_t file_entry_encoded_size(const vw_file_entry_t *e) {
    return 1u + 8u + 8u + 8u + 8u + 8u + 2u + (uint32_t)strlen(e->name);
}
static uint8_t *write_file_entry(uint8_t *p, const vw_file_entry_t *e) {
    *p++ = e->entry_type;
    vw_write_u64le(p, e->file_id);              p += 8;
    vw_write_u64le(p, e->size_bytes);            p += 8;
    vw_write_u64le(p, (uint64_t)e->mtime_unix);  p += 8;
    vw_write_u64le(p, e->version_id);            p += 8;
    vw_write_u64le(p, e->vault_id);              p += 8;
    uint16_t nlen = (uint16_t)strlen(e->name);
    vw_write_u16le(p, nlen); p += 2;
    memcpy(p, e->name, nlen); p += nlen;
    return p;
}
static jbyteArray encode_file_entries(JNIEnv *env, const vw_file_entry_t *entries, uint32_t count) {
    uint32_t total = 4;
    for (uint32_t i = 0; i < count; i++) total += file_entry_encoded_size(&entries[i]);
    uint8_t *buf = malloc(total);
    if (!buf) return NULL;
    uint8_t *p = buf;
    vw_write_u32le(p, count); p += 4;
    for (uint32_t i = 0; i < count; i++) p = write_file_entry(p, &entries[i]);
    jbyteArray arr = make_byte_array(env, buf, total);
    free(buf);
    return arr;
}

static uint32_t share_entry_encoded_size(const vw_share_entry_t *e) {
    return 8u + 8u + 2u + (uint32_t)strlen(e->name) + 1u
         + 2u + (uint32_t)strlen(e->target_username) + 1u + 8u + 8u + 1u;
}
static uint8_t *write_share_entry(uint8_t *p, const vw_share_entry_t *e) {
    vw_write_u64le(p, e->share_id); p += 8;
    vw_write_u64le(p, e->file_id);  p += 8;
    uint16_t nlen = (uint16_t)strlen(e->name);
    vw_write_u16le(p, nlen); p += 2;
    memcpy(p, e->name, nlen); p += nlen;
    *p++ = e->share_type;
    uint16_t tlen = (uint16_t)strlen(e->target_username);
    vw_write_u16le(p, tlen); p += 2;
    memcpy(p, e->target_username, tlen); p += tlen;
    *p++ = e->permission;
    vw_write_u64le(p, (uint64_t)e->created_at); p += 8;
    vw_write_u64le(p, (uint64_t)e->expires_at); p += 8;
    *p++ = e->revoked;
    return p;
}
static jbyteArray encode_share_entries(JNIEnv *env, const vw_share_entry_t *entries, uint32_t count) {
    uint32_t total = 4;
    for (uint32_t i = 0; i < count; i++) total += share_entry_encoded_size(&entries[i]);
    uint8_t *buf = malloc(total);
    if (!buf) return NULL;
    uint8_t *p = buf;
    vw_write_u32le(p, count); p += 4;
    for (uint32_t i = 0; i < count; i++) p = write_share_entry(p, &entries[i]);
    jbyteArray arr = make_byte_array(env, buf, total);
    free(buf);
    return arr;
}

static uint32_t link_entry_encoded_size(const vw_link_entry_t *e) {
    return 8u + 8u + 2u + (uint32_t)strlen(e->name) + 1u + 8u + 8u + 1u + 1u;
}
static uint8_t *write_link_entry(uint8_t *p, const vw_link_entry_t *e) {
    vw_write_u64le(p, e->share_id); p += 8;
    vw_write_u64le(p, e->file_id);  p += 8;
    uint16_t nlen = (uint16_t)strlen(e->name);
    vw_write_u16le(p, nlen); p += 2;
    memcpy(p, e->name, nlen); p += nlen;
    *p++ = e->permission;
    vw_write_u64le(p, (uint64_t)e->created_at); p += 8;
    vw_write_u64le(p, (uint64_t)e->expires_at); p += 8;
    *p++ = e->revoked;
    *p++ = e->has_password;
    return p;
}
static jbyteArray encode_link_entries(JNIEnv *env, const vw_link_entry_t *entries, uint32_t count) {
    uint32_t total = 4;
    for (uint32_t i = 0; i < count; i++) total += link_entry_encoded_size(&entries[i]);
    uint8_t *buf = malloc(total);
    if (!buf) return NULL;
    uint8_t *p = buf;
    vw_write_u32le(p, count); p += 4;
    for (uint32_t i = 0; i < count; i++) p = write_link_entry(p, &entries[i]);
    jbyteArray arr = make_byte_array(env, buf, total);
    free(buf);
    return arr;
}

#define VERSION_ENTRY_SIZE 24u /* u64 version_id + i64 created_at + u64 size_bytes; no strings */
static uint8_t *write_version_entry(uint8_t *p, const vw_version_entry_t *e) {
    vw_write_u64le(p, e->version_id);           p += 8;
    vw_write_u64le(p, (uint64_t)e->created_at); p += 8;
    vw_write_u64le(p, e->size_bytes);           p += 8;
    return p;
}
static jbyteArray encode_version_entries(JNIEnv *env, const vw_version_entry_t *entries, uint32_t count) {
    uint32_t total = 4 + count * VERSION_ENTRY_SIZE;
    uint8_t *buf = malloc(total);
    if (!buf) return NULL;
    uint8_t *p = buf;
    vw_write_u32le(p, count); p += 4;
    for (uint32_t i = 0; i < count; i++) p = write_version_entry(p, &entries[i]);
    jbyteArray arr = make_byte_array(env, buf, total);
    free(buf);
    return arr;
}

#define VAULT_ENTRY_SIZE 24u /* u64 vault_id + u64 folder_file_id + i64 created_at; no strings */
static uint8_t *write_vault_entry(uint8_t *p, const vw_vault_entry_t *e) {
    vw_write_u64le(p, e->vault_id);              p += 8;
    vw_write_u64le(p, e->folder_file_id);        p += 8;
    vw_write_u64le(p, (uint64_t)e->created_at);  p += 8;
    return p;
}
static jbyteArray encode_vault_entries(JNIEnv *env, const vw_vault_entry_t *entries, uint32_t count) {
    uint32_t total = 4 + count * VAULT_ENTRY_SIZE;
    uint8_t *buf = malloc(total);
    if (!buf) return NULL;
    uint8_t *p = buf;
    vw_write_u32le(p, count); p += 4;
    for (uint32_t i = 0; i < count; i++) p = write_vault_entry(p, &entries[i]);
    jbyteArray arr = make_byte_array(env, buf, total);
    free(buf);
    return arr;
}

/* ── Session lifecycle ────────────────────────────────────────────────── */

/* Trivial OTP callback: the code was already collected by the Kotlin UI
 * before this connect attempt (see vw_jni_bridge.h's nativeConnect doc) —
 * no real async native-to-Java callback needed, matching the existing
 * vw_gui_ipc/account_add precedent on desktop. */
typedef struct { const char *otp; } otp_ctx_t;
static vw_err_t otp_callback(void *userdata, char *otp_buf, uint16_t *otp_len) {
    const otp_ctx_t *ctx = (const otp_ctx_t *)userdata;
    size_t len = strlen(ctx->otp);
    if (len > 8) len = 8; /* otp_buf guaranteed >=16 bytes; codes are <=8 ASCII digits */
    memcpy(otp_buf, ctx->otp, len);
    *otp_len = (uint16_t)len;
    return VW_OK;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeConnect(
    JNIEnv *env, jobject thiz,
    jstring host, jint port, jstring ca_cert_pem_path,
    jstring username, jbyteArray password, jstring otp)
{
    (void)thiz;

    const char *host_c = borrow_str(env, host);
    const char *ca_path_c = borrow_str(env, ca_cert_pem_path);
    const char *username_c = borrow_str(env, username);
    const char *otp_c = borrow_str(env, otp);
    if (!host_c || !ca_path_c || !username_c || !otp_c || !password) {
        release_str(env, host, host_c);
        release_str(env, ca_cert_pem_path, ca_path_c);
        release_str(env, username, username_c);
        release_str(env, otp, otp_c);
        g_last_error = VW_ERR_INVALID_ARG;
        return 0;
    }

    jbyte *password_bytes = (*env)->GetByteArrayElements(env, password, NULL);
    jsize password_len = (*env)->GetArrayLength(env, password);
    if (!password_bytes) {
        release_str(env, host, host_c);
        release_str(env, ca_cert_pem_path, ca_path_c);
        release_str(env, username, username_c);
        release_str(env, otp, otp_c);
        g_last_error = VW_ERR_OOM;
        return 0;
    }

    vw_client_cfg_t cfg = {
        .host = host_c,
        .port = (uint16_t)port,
        .cert_verify = (ca_path_c[0] == '\0') ? VW_CERT_VERIFY_NONE
                                               : VW_CERT_VERIFY_REQUIRED,
        .ca_cert_pem_path = (ca_path_c[0] == '\0') ? NULL : ca_path_c,
        .conn_opts = NULL,
    };

    otp_ctx_t otp_ctx = { .otp = otp_c };
    vw_otp_callback_t otp_cb = (otp_c[0] != '\0') ? otp_callback : NULL;
    void *otp_userdata = (otp_c[0] != '\0') ? (void *)&otp_ctx : NULL;

    vw_client_sess_t *sess = NULL;
    vw_err_t rc = vw_client_connect(&cfg,
                                     username_c, (uint16_t)strlen(username_c),
                                     password_bytes, (size_t)password_len,
                                     otp_cb, otp_userdata,
                                     &sess);

    release_str(env, host, host_c);
    release_str(env, ca_cert_pem_path, ca_path_c);
    release_str(env, username, username_c);
    release_str(env, otp, otp_c);
    /* password_bytes is our own copy of the plaintext password (STYLE.md
     * §15: zero secrets before release, same as every comparable buffer in
     * vw_client_core.c itself). */
    vw_crypto_secure_zero(password_bytes, (size_t)password_len);
    (*env)->ReleaseByteArrayElements(env, password, password_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) {
        LOGE("vw_client_connect failed: err=%d", (int)rc);
        return 0;
    }
    return (jlong)(intptr_t)sess;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeConnectWithHash(
    JNIEnv *env, jobject thiz,
    jstring host, jint port, jstring ca_cert_pem_path,
    jstring username, jbyteArray auth_token, jstring otp)
{
    (void)thiz;

    const char *host_c = borrow_str(env, host);
    const char *ca_path_c = borrow_str(env, ca_cert_pem_path);
    const char *username_c = borrow_str(env, username);
    const char *otp_c = borrow_str(env, otp);
    if (!host_c || !ca_path_c || !username_c || !otp_c || !auth_token ||
        (*env)->GetArrayLength(env, auth_token) != VW_TOKEN_BYTES) {
        release_str(env, host, host_c);
        release_str(env, ca_cert_pem_path, ca_path_c);
        release_str(env, username, username_c);
        release_str(env, otp, otp_c);
        g_last_error = VW_ERR_INVALID_ARG;
        return 0;
    }

    jbyte *token_bytes = (*env)->GetByteArrayElements(env, auth_token, NULL);
    if (!token_bytes) {
        release_str(env, host, host_c);
        release_str(env, ca_cert_pem_path, ca_path_c);
        release_str(env, username, username_c);
        release_str(env, otp, otp_c);
        g_last_error = VW_ERR_OOM;
        return 0;
    }

    vw_client_cfg_t cfg = {
        .host = host_c,
        .port = (uint16_t)port,
        .cert_verify = (ca_path_c[0] == '\0') ? VW_CERT_VERIFY_NONE
                                               : VW_CERT_VERIFY_REQUIRED,
        .ca_cert_pem_path = (ca_path_c[0] == '\0') ? NULL : ca_path_c,
        .conn_opts = NULL,
    };

    otp_ctx_t otp_ctx = { .otp = otp_c };
    vw_otp_callback_t otp_cb = (otp_c[0] != '\0') ? otp_callback : NULL;
    void *otp_userdata = (otp_c[0] != '\0') ? (void *)&otp_ctx : NULL;

    vw_client_sess_t *sess = NULL;
    vw_err_t rc = vw_client_connect_with_hash(&cfg,
                                               username_c, (uint16_t)strlen(username_c),
                                               (const uint8_t *)token_bytes,
                                               otp_cb, otp_userdata,
                                               &sess);

    release_str(env, host, host_c);
    release_str(env, ca_cert_pem_path, ca_path_c);
    release_str(env, username, username_c);
    release_str(env, otp, otp_c);
    vw_crypto_secure_zero(token_bytes, VW_TOKEN_BYTES);
    (*env)->ReleaseByteArrayElements(env, auth_token, token_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) return 0;
    return (jlong)(intptr_t)sess;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeSessionResume(
    JNIEnv *env, jobject thiz,
    jstring host, jint port, jstring ca_cert_pem_path,
    jbyteArray saved_token)
{
    (void)thiz;

    const char *host_c = borrow_str(env, host);
    const char *ca_path_c = borrow_str(env, ca_cert_pem_path);
    if (!host_c || !ca_path_c || !saved_token ||
        (*env)->GetArrayLength(env, saved_token) != VW_TOKEN_BYTES) {
        release_str(env, host, host_c);
        release_str(env, ca_cert_pem_path, ca_path_c);
        g_last_error = VW_ERR_INVALID_ARG;
        return 0;
    }

    jbyte *token_bytes = (*env)->GetByteArrayElements(env, saved_token, NULL);
    if (!token_bytes) {
        release_str(env, host, host_c);
        release_str(env, ca_cert_pem_path, ca_path_c);
        g_last_error = VW_ERR_OOM;
        return 0;
    }

    vw_client_cfg_t cfg = {
        .host = host_c,
        .port = (uint16_t)port,
        .cert_verify = (ca_path_c[0] == '\0') ? VW_CERT_VERIFY_NONE
                                               : VW_CERT_VERIFY_REQUIRED,
        .ca_cert_pem_path = (ca_path_c[0] == '\0') ? NULL : ca_path_c,
        .conn_opts = NULL,
    };

    vw_client_sess_t *sess = NULL;
    vw_err_t rc = vw_client_resume(&cfg, (const uint8_t *)token_bytes, &sess);

    release_str(env, host, host_c);
    release_str(env, ca_cert_pem_path, ca_path_c);
    vw_crypto_secure_zero(token_bytes, VW_TOKEN_BYTES);
    (*env)->ReleaseByteArrayElements(env, saved_token, token_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) return 0;
    return (jlong)(intptr_t)sess;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeGetToken(JNIEnv *env, jobject thiz, jlong session_handle)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    uint8_t token[VW_TOKEN_BYTES];
    vw_client_get_token(sess, token);
    jbyteArray arr = make_byte_array(env, token, VW_TOKEN_BYTES);
    vw_crypto_secure_zero(token, VW_TOKEN_BYTES);
    return arr;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeUserId(JNIEnv *env, jobject thiz, jlong session_handle)
{
    (void)env; (void)thiz;
    return (jlong)vw_client_user_id_of((vw_client_sess_t *)(intptr_t)session_handle);
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeExpiresAt(JNIEnv *env, jobject thiz, jlong session_handle)
{
    (void)env; (void)thiz;
    return (jlong)vw_client_expires_at_of((vw_client_sess_t *)(intptr_t)session_handle);
}

JNIEXPORT jboolean JNICALL
Java_com_vaporwault_client_VwNative_nativeIsAdmin(JNIEnv *env, jobject thiz, jlong session_handle)
{
    (void)env; (void)thiz;
    return vw_client_is_admin_of((vw_client_sess_t *)(intptr_t)session_handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeLastError(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)g_last_error;
}

JNIEXPORT void JNICALL
Java_com_vaporwault_client_VwNative_nativeLogout(JNIEnv *env, jobject thiz,
                                                  jlong session_handle)
{
    (void)env;
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    vw_client_logout(sess);
}

/* ── File operations ──────────────────────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileList(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jstring virtual_path,
                                                    jboolean recursive)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *path_c = borrow_str(env, virtual_path);
    if (!path_c) { g_last_error = VW_ERR_INVALID_ARG; return NULL; }

    vw_file_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t rc = vw_client_file_list(sess, path_c, recursive ? 1 : 0, &entries, &count);
    release_str(env, virtual_path, path_c);

    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    jbyteArray result = encode_file_entries(env, entries, count);
    free(entries);
    if (!result) g_last_error = VW_ERR_OOM;
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileListById(JNIEnv *env, jobject thiz,
                                                        jlong session_handle,
                                                        jlong dir_file_id,
                                                        jboolean recursive)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    vw_file_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t rc = vw_client_file_list_by_id(sess, (uint64_t)dir_file_id, recursive ? 1 : 0,
                                             &entries, &count);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    jbyteArray result = encode_file_entries(env, entries, count);
    free(entries);
    if (!result) g_last_error = VW_ERR_OOM;
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileStat(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jstring virtual_path)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *path_c = borrow_str(env, virtual_path);
    if (!path_c) { g_last_error = VW_ERR_INVALID_ARG; return NULL; }

    vw_file_entry_t entry;
    vw_err_t rc = vw_client_file_stat(sess, path_c, &entry);
    release_str(env, virtual_path, path_c);

    g_last_error = rc;
    if (rc != VW_OK) return NULL;

    uint32_t sz = file_entry_encoded_size(&entry);
    uint8_t *buf = malloc(sz);
    if (!buf) { g_last_error = VW_ERR_OOM; return NULL; }
    write_file_entry(buf, &entry);
    jbyteArray result = make_byte_array(env, buf, sz);
    free(buf);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileStatById(JNIEnv *env, jobject thiz,
                                                        jlong session_handle,
                                                        jlong file_id)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    vw_file_entry_t entry;
    vw_err_t rc = vw_client_file_stat_by_id(sess, (uint64_t)file_id, &entry);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;

    uint32_t sz = file_entry_encoded_size(&entry);
    uint8_t *buf = malloc(sz);
    if (!buf) { g_last_error = VW_ERR_OOM; return NULL; }
    write_file_entry(buf, &entry);
    jbyteArray result = make_byte_array(env, buf, sz);
    free(buf);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeFileDelete(JNIEnv *env, jobject thiz,
                                                      jlong session_handle,
                                                      jstring virtual_path)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *path_c = borrow_str(env, virtual_path);
    if (!path_c) return (jint)VW_ERR_INVALID_ARG;
    vw_err_t rc = vw_client_file_delete(sess, path_c);
    release_str(env, virtual_path, path_c);
    return (jint)rc;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeFileDeleteById(JNIEnv *env, jobject thiz,
                                                          jlong session_handle,
                                                          jlong file_id)
{
    (void)env; (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    return (jint)vw_client_file_delete_by_id(sess, (uint64_t)file_id);
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeFileMove(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jlong file_id,
                                                    jlong new_parent_dir_id,
                                                    jstring new_name)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *name_c = borrow_str(env, new_name);
    if (!name_c) return (jint)VW_ERR_INVALID_ARG;
    vw_err_t rc = vw_client_file_move(sess, (uint64_t)file_id, (uint64_t)new_parent_dir_id, name_c);
    release_str(env, new_name, name_c);
    return (jint)rc;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeFileMkdir(JNIEnv *env, jobject thiz,
                                                     jlong session_handle,
                                                     jlong new_parent_dir_id,
                                                     jstring name)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *name_c = borrow_str(env, name);
    if (!name_c) { g_last_error = VW_ERR_INVALID_ARG; return 0; }

    uint64_t dir_id = 0;
    vw_err_t rc = vw_client_file_mkdir(sess, (uint64_t)new_parent_dir_id, name_c, &dir_id);
    release_str(env, name, name_c);
    g_last_error = rc;
    return (rc == VW_OK) ? (jlong)dir_id : 0;
}

/* ── Chunked transfer primitives ──────────────────────────────────────── */

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeChunkUploadIfMissing(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jbyteArray hash, jobject data, jint len)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;

    if (!hash || (*env)->GetArrayLength(env, hash) != VW_HASH_BYTES || len < 0) {
        g_last_error = VW_ERR_INVALID_ARG;
        return (jint)VW_ERR_INVALID_ARG;
    }
    void *addr = (*env)->GetDirectBufferAddress(env, data);
    jlong capacity = (*env)->GetDirectBufferCapacity(env, data);
    if (!addr || capacity < (jlong)len) {
        g_last_error = VW_ERR_INVALID_ARG;
        return (jint)VW_ERR_INVALID_ARG;
    }
    jbyte *hash_bytes = (*env)->GetByteArrayElements(env, hash, NULL);
    if (!hash_bytes) { g_last_error = VW_ERR_OOM; return (jint)VW_ERR_OOM; }

    vw_err_t rc = vw_client_chunk_upload_if_missing(sess, (const uint8_t *)hash_bytes,
                                                     addr, (uint32_t)len);
    (*env)->ReleaseByteArrayElements(env, hash, hash_bytes, JNI_ABORT);
    g_last_error = rc;
    return (jint)rc;
}

JNIEXPORT jlongArray JNICALL
Java_com_vaporwault_client_VwNative_nativeFileCommit(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong file_id, jstring name_or_path,
    jlong logical_size, jbyteArray chunk_hashes,
    jlong vault_id, jbyteArray wrapped_dek)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;

    const char *name_c = borrow_str(env, name_or_path);
    if (!name_c) { g_last_error = VW_ERR_INVALID_ARG; return NULL; }

    jsize hashes_len = chunk_hashes ? (*env)->GetArrayLength(env, chunk_hashes) : 0;
    if (hashes_len % VW_HASH_BYTES != 0) {
        release_str(env, name_or_path, name_c);
        g_last_error = VW_ERR_INVALID_ARG;
        return NULL;
    }
    uint32_t chunk_count = (uint32_t)(hashes_len / VW_HASH_BYTES);
    jbyte *hashes_bytes = chunk_count ? (*env)->GetByteArrayElements(env, chunk_hashes, NULL) : NULL;
    if (chunk_count && !hashes_bytes) {
        release_str(env, name_or_path, name_c);
        g_last_error = VW_ERR_OOM;
        return NULL;
    }

    jbyte *dek_bytes = NULL;
    jsize dek_len = 0;
    if (wrapped_dek) {
        dek_len = (*env)->GetArrayLength(env, wrapped_dek);
        dek_bytes = (*env)->GetByteArrayElements(env, wrapped_dek, NULL);
    }

    uint64_t out_file_id = 0, out_version_id = 0;
    vw_err_t rc = vw_client_file_commit_raw(sess, (uint64_t)file_id, name_c, (uint16_t)strlen(name_c),
                                             (uint64_t)logical_size, chunk_count,
                                             (const uint8_t *)hashes_bytes,
                                             (uint64_t)vault_id,
                                             (const uint8_t *)dek_bytes, (uint16_t)dek_len,
                                             &out_file_id, &out_version_id);

    release_str(env, name_or_path, name_c);
    if (hashes_bytes) (*env)->ReleaseByteArrayElements(env, chunk_hashes, hashes_bytes, JNI_ABORT);
    if (dek_bytes) (*env)->ReleaseByteArrayElements(env, wrapped_dek, dek_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) return NULL;

    jlong result[2] = { (jlong)out_file_id, (jlong)out_version_id };
    jlongArray arr = (*env)->NewLongArray(env, 2);
    if (arr) (*env)->SetLongArrayRegion(env, arr, 0, 2, result);
    return arr;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionChunksRaw(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong version_id)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;

    uint8_t *hashes = NULL;
    uint32_t chunk_count = 0;
    uint64_t vault_id = 0;
    uint8_t *wrapped_dek = NULL;
    uint16_t wrapped_dek_len = 0;

    vw_err_t rc = vw_client_version_chunks_raw(sess, (uint64_t)version_id,
                                                &hashes, &chunk_count,
                                                &vault_id, &wrapped_dek, &wrapped_dek_len);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;

    uint32_t total = 4u + 8u + 2u + wrapped_dek_len + chunk_count * VW_HASH_BYTES;
    uint8_t *buf = malloc(total);
    if (!buf) {
        free(hashes);
        free(wrapped_dek);
        g_last_error = VW_ERR_OOM;
        return NULL;
    }
    uint8_t *p = buf;
    vw_write_u32le(p, chunk_count); p += 4;
    vw_write_u64le(p, vault_id);    p += 8;
    vw_write_u16le(p, wrapped_dek_len); p += 2;
    if (wrapped_dek_len) { memcpy(p, wrapped_dek, wrapped_dek_len); p += wrapped_dek_len; }
    if (chunk_count) memcpy(p, hashes, (size_t)chunk_count * VW_HASH_BYTES);

    jbyteArray result = make_byte_array(env, buf, total);
    free(buf);
    free(hashes);
    free(wrapped_dek);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeChunkDownloadRaw(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jbyteArray hash, jobject out, jint out_capacity)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;

    if (!hash || (*env)->GetArrayLength(env, hash) != VW_HASH_BYTES || out_capacity < 0) {
        g_last_error = VW_ERR_INVALID_ARG;
        return -1;
    }
    void *addr = (*env)->GetDirectBufferAddress(env, out);
    jlong capacity = (*env)->GetDirectBufferCapacity(env, out);
    if (!addr || capacity < (jlong)out_capacity) {
        g_last_error = VW_ERR_INVALID_ARG;
        return -1;
    }
    jbyte *hash_bytes = (*env)->GetByteArrayElements(env, hash, NULL);
    if (!hash_bytes) { g_last_error = VW_ERR_OOM; return -1; }

    uint8_t *data = NULL;
    uint32_t len = 0;
    vw_err_t rc = vw_client_chunk_download_raw(sess, (const uint8_t *)hash_bytes, &data, &len);
    (*env)->ReleaseByteArrayElements(env, hash, hash_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) { free(data); return -1; }

    if ((jlong)len > (jlong)out_capacity) {
        free(data);
        g_last_error = VW_ERR_PROTO_TOO_LARGE;
        return -1;
    }
    memcpy(addr, data, len);
    free(data);
    return (jint)len;
}

/* ── Version history ──────────────────────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionList(JNIEnv *env, jobject thiz,
                                                       jlong session_handle,
                                                       jstring virtual_path)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *path_c = borrow_str(env, virtual_path);
    if (!path_c) { g_last_error = VW_ERR_INVALID_ARG; return NULL; }

    vw_version_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t rc = vw_client_version_list(sess, path_c, &entries, &count);
    release_str(env, virtual_path, path_c);

    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    jbyteArray result = encode_version_entries(env, entries, count);
    free(entries);
    if (!result) g_last_error = VW_ERR_OOM;
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionListById(JNIEnv *env, jobject thiz,
                                                           jlong session_handle,
                                                           jlong file_id)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    vw_version_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t rc = vw_client_version_list_by_id(sess, (uint64_t)file_id, &entries, &count);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    jbyteArray result = encode_version_entries(env, entries, count);
    free(entries);
    if (!result) g_last_error = VW_ERR_OOM;
    return result;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionRestore(JNIEnv *env, jobject thiz,
                                                          jlong session_handle,
                                                          jstring virtual_path,
                                                          jlong version_id)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *path_c = borrow_str(env, virtual_path);
    if (!path_c) return (jint)VW_ERR_INVALID_ARG;
    vw_err_t rc = vw_client_version_restore(sess, path_c, (uint64_t)version_id);
    release_str(env, virtual_path, path_c);
    return (jint)rc;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeVersionRestoreById(JNIEnv *env, jobject thiz,
                                                              jlong session_handle,
                                                              jlong version_id)
{
    (void)env; (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    return (jint)vw_client_version_restore_by_id(sess, (uint64_t)version_id);
}

/* ── Sharing ───────────────────────────────────────────────────────────── */

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeShareGrant(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong file_id, jstring target_username,
    jint permission, jlong expires_at)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *user_c = borrow_str(env, target_username);
    if (!user_c) { g_last_error = VW_ERR_INVALID_ARG; return 0; }

    uint64_t share_id = 0;
    vw_err_t rc = vw_client_share_grant(sess, (uint64_t)file_id, user_c,
                                         (vw_perm_t)permission, (int64_t)expires_at, &share_id);
    release_str(env, target_username, user_c);
    g_last_error = rc;
    return (rc == VW_OK) ? (jlong)share_id : 0;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeShareRevoke(JNIEnv *env, jobject thiz,
                                                       jlong session_handle,
                                                       jlong share_id)
{
    (void)env; (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    return (jint)vw_client_share_revoke(sess, (uint64_t)share_id);
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeShareList(JNIEnv *env, jobject thiz,
                                                     jlong session_handle,
                                                     jint mode)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    vw_share_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t rc = vw_client_share_list(sess, (uint8_t)mode, &entries, &count);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    jbyteArray result = encode_share_entries(env, entries, count);
    free(entries);
    if (!result) g_last_error = VW_ERR_OOM;
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeLinkCreate(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong file_id, jint permission,
    jlong expires_at, jstring password)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *pass_c = borrow_str(env, password);
    if (!pass_c) { g_last_error = VW_ERR_INVALID_ARG; return NULL; }

    uint64_t share_id = 0;
    uint8_t token[32];
    vw_err_t rc = vw_client_link_create(sess, (uint64_t)file_id, (vw_perm_t)permission,
                                         (int64_t)expires_at,
                                         pass_c[0] ? pass_c : NULL,
                                         &share_id, token);
    release_str(env, password, pass_c);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;

    uint8_t buf[40];
    vw_write_u64le(buf, share_id);
    memcpy(buf + 8, token, 32);
    jbyteArray result = make_byte_array(env, buf, sizeof(buf));
    /* The raw link token is a bearer credential — as sensitive as a
     * session token — zero our local copies once handed to the JVM. */
    vw_crypto_secure_zero(token, sizeof(token));
    vw_crypto_secure_zero(buf, sizeof(buf));
    return result;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeLinkRevoke(JNIEnv *env, jobject thiz,
                                                      jlong session_handle,
                                                      jlong share_id)
{
    (void)env; (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    return (jint)vw_client_link_revoke(sess, (uint64_t)share_id);
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeLinkList(JNIEnv *env, jobject thiz,
                                                    jlong session_handle,
                                                    jlong file_id_filter)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    vw_link_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t rc = vw_client_link_list(sess, (uint64_t)file_id_filter, &entries, &count);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    jbyteArray result = encode_link_entries(env, entries, count);
    free(entries);
    if (!result) g_last_error = VW_ERR_OOM;
    return result;
}

/* ── Account self-service ──────────────────────────────────────────────── */

JNIEXPORT jstring JNICALL
Java_com_vaporwault_client_VwNative_nativeAccountEmailGet(JNIEnv *env, jobject thiz,
                                                           jlong session_handle)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    char email[129];
    vw_err_t rc = vw_client_account_email_get(sess, email, sizeof(email));
    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    return (*env)->NewStringUTF(env, email);
}

JNIEXPORT jstring JNICALL
Java_com_vaporwault_client_VwNative_nativeAccountEmailSet(JNIEnv *env, jobject thiz,
                                                           jlong session_handle,
                                                           jstring email)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    const char *email_c = borrow_str(env, email);
    if (!email_c) { g_last_error = VW_ERR_INVALID_ARG; return NULL; }

    char out_email[129];
    vw_err_t rc = vw_client_account_email_set(sess, email_c, out_email, sizeof(out_email));
    release_str(env, email, email_c);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    return (*env)->NewStringUTF(env, out_email);
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeAccount2faGet(JNIEnv *env, jobject thiz,
                                                         jlong session_handle)
{
    (void)env; (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    uint8_t enabled = 0;
    vw_err_t rc = vw_client_account_2fa_get(sess, &enabled);
    g_last_error = rc;
    if (rc != VW_OK) return -1;
    return enabled ? 1 : 0;
}

JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeAccount2faSet(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jbyteArray password, jboolean enable)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    if (!password) { g_last_error = VW_ERR_INVALID_ARG; return -1; }

    jbyte *password_bytes = (*env)->GetByteArrayElements(env, password, NULL);
    jsize password_len = (*env)->GetArrayLength(env, password);
    if (!password_bytes) { g_last_error = VW_ERR_OOM; return -1; }

    uint8_t enabled = 0;
    vw_err_t rc = vw_client_account_2fa_set(sess, password_bytes, (size_t)password_len,
                                             enable ? 1 : 0, &enabled);

    vw_crypto_secure_zero(password_bytes, (size_t)password_len);
    (*env)->ReleaseByteArrayElements(env, password, password_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) return -1;
    return enabled ? 1 : 0;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeNotifyPrefsGet(JNIEnv *env, jobject thiz,
                                                          jlong session_handle)
{
    (void)env; (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    uint32_t prefs = 0;
    vw_err_t rc = vw_client_notify_prefs_get(sess, &prefs);
    g_last_error = rc;
    if (rc != VW_OK) return -1;
    return (jlong)prefs;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeNotifyPrefsSet(JNIEnv *env, jobject thiz,
                                                          jlong session_handle,
                                                          jlong prefs)
{
    (void)env; (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    uint32_t out_prefs = 0;
    vw_err_t rc = vw_client_notify_prefs_set(sess, (uint32_t)prefs, &out_prefs);
    g_last_error = rc;
    if (rc != VW_OK) return -1;
    return (jlong)out_prefs;
}

/* ── Vault (TASK-230) ─────────────────────────────────────────────────────
 * All key-derivation/wrapping/unwrapping crypto lives in vw_vault.c
 * (unmodified, cross-compiled from src/client/ same as vw_client_core.c) —
 * this bridge only moves the passphrase in as raw bytes and the resulting
 * opaque vault handle out; see vw_vault.h's own header comment for the
 * envelope design. A "vault handle" is a vw_vault_t* cast to jlong, same
 * intptr_t round trip as a session handle. kdf_params is always NULL here
 * (the SEC.07-pinned floor) — this bridge does not expose a way to pick
 * weaker-than-floor params, matching vw_vault_setup's own doc comment on
 * what a NULL kdf_params means. */

JNIEXPORT jlongArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVaultSetup(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong folder_file_id, jbyteArray passphrase)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    if (!passphrase) { g_last_error = VW_ERR_INVALID_ARG; return NULL; }

    jbyte *pass_bytes = (*env)->GetByteArrayElements(env, passphrase, NULL);
    jsize pass_len = (*env)->GetArrayLength(env, passphrase);
    if (!pass_bytes) { g_last_error = VW_ERR_OOM; return NULL; }

    vw_vault_t *vault = NULL;
    uint64_t vault_id = 0;
    vw_err_t rc = vw_vault_setup(sess, (uint64_t)folder_file_id,
                                  pass_bytes, (size_t)pass_len,
                                  NULL, &vault, &vault_id);

    vw_crypto_secure_zero(pass_bytes, (size_t)pass_len);
    (*env)->ReleaseByteArrayElements(env, passphrase, pass_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) return NULL;

    jlong result[2] = { (jlong)(intptr_t)vault, (jlong)vault_id };
    jlongArray arr = (*env)->NewLongArray(env, 2);
    if (arr) (*env)->SetLongArrayRegion(env, arr, 0, 2, result);
    return arr;
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeVaultUnlock(
    JNIEnv *env, jobject thiz,
    jlong session_handle, jlong vault_id, jbyteArray passphrase)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    if (!passphrase) { g_last_error = VW_ERR_INVALID_ARG; return 0; }

    jbyte *pass_bytes = (*env)->GetByteArrayElements(env, passphrase, NULL);
    jsize pass_len = (*env)->GetArrayLength(env, passphrase);
    if (!pass_bytes) { g_last_error = VW_ERR_OOM; return 0; }

    vw_vault_t *vault = NULL;
    vw_err_t rc = vw_vault_unlock(sess, (uint64_t)vault_id,
                                   pass_bytes, (size_t)pass_len, &vault);

    vw_crypto_secure_zero(pass_bytes, (size_t)pass_len);
    (*env)->ReleaseByteArrayElements(env, passphrase, pass_bytes, JNI_ABORT);

    g_last_error = rc;
    if (rc != VW_OK) return 0;
    return (jlong)(intptr_t)vault;
}

JNIEXPORT void JNICALL
Java_com_vaporwault_client_VwNative_nativeVaultClose(JNIEnv *env, jobject thiz, jlong vault_handle)
{
    (void)env; (void)thiz;
    vw_vault_close((vw_vault_t *)(intptr_t)vault_handle);
}

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeVaultFolderFileId(JNIEnv *env, jobject thiz, jlong vault_handle)
{
    (void)env; (void)thiz;
    return (jlong)vw_vault_folder_file_id_of((const vw_vault_t *)(intptr_t)vault_handle);
}

JNIEXPORT jbyteArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVaultList(JNIEnv *env, jobject thiz, jlong session_handle)
{
    (void)thiz;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;
    vw_vault_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t rc = vw_client_vault_list(sess, &entries, &count);
    g_last_error = rc;
    if (rc != VW_OK) return NULL;
    jbyteArray result = encode_vault_entries(env, entries, count);
    free(entries);
    if (!result) g_last_error = VW_ERR_OOM;
    return result;
}

/* file_id == 0 creates a new file named leaf_name inside the vault's
 * folder; file_id != 0 uploads a new version of that existing file (see
 * vw_vault_upload_file's own doc comment — leaf_name is ignored in that
 * case). local_path is a real POSIX path in the app's private cache
 * (android/app's SAF content:// URIs cannot be handed to vw_vault.c's
 * whole-file upload directly — see VaultTransferer.kt). No live progress
 * callback in this first cut (progress_cb=NULL): a real native-to-Java
 * callback is a nontrivial new pattern for this bridge and TASK-230's
 * acceptance criteria don't require it — the UI shows an indeterminate
 * "Encrypting…" status for the duration of this one blocking call instead,
 * disclosed as a scope simplification in the task's Notes. */
JNIEXPORT jlongArray JNICALL
Java_com_vaporwault_client_VwNative_nativeVaultUploadFile(
    JNIEnv *env, jobject thiz,
    jlong vault_handle, jlong session_handle, jlong file_id,
    jstring leaf_name, jstring local_path)
{
    (void)thiz;
    vw_vault_t *vault = (vw_vault_t *)(intptr_t)vault_handle;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;

    const char *leaf_c = borrow_str(env, leaf_name);
    const char *path_c = borrow_str(env, local_path);
    if (!path_c) {
        release_str(env, leaf_name, leaf_c);
        release_str(env, local_path, path_c);
        g_last_error = VW_ERR_INVALID_ARG;
        return NULL;
    }

    uint64_t out_file_id = 0, out_version_id = 0;
    vw_err_t rc = vw_vault_upload_file(vault, sess, (uint64_t)file_id,
                                        leaf_c ? leaf_c : "", path_c,
                                        NULL, NULL,
                                        &out_file_id, &out_version_id);

    release_str(env, leaf_name, leaf_c);
    release_str(env, local_path, path_c);

    g_last_error = rc;
    if (rc != VW_OK) return NULL;

    jlong result[2] = { (jlong)out_file_id, (jlong)out_version_id };
    jlongArray arr = (*env)->NewLongArray(env, 2);
    if (arr) (*env)->SetLongArrayRegion(env, arr, 0, 2, result);
    return arr;
}

/* local_path is where the decrypted plaintext is written (a real POSIX
 * path in the app's private cache — see VaultTransferer.kt for the copy
 * to/from the user's chosen SAF destination). */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeVaultDownloadFile(
    JNIEnv *env, jobject thiz,
    jlong vault_handle, jlong session_handle, jlong file_id, jstring local_path)
{
    (void)thiz;
    vw_vault_t *vault = (vw_vault_t *)(intptr_t)vault_handle;
    vw_client_sess_t *sess = (vw_client_sess_t *)(intptr_t)session_handle;

    const char *path_c = borrow_str(env, local_path);
    if (!path_c) { g_last_error = VW_ERR_INVALID_ARG; return (jint)VW_ERR_INVALID_ARG; }

    vw_err_t rc = vw_vault_download_file(vault, sess, (uint64_t)file_id, path_c, NULL, NULL);
    release_str(env, local_path, path_c);

    g_last_error = rc;
    return (jint)rc;
}
