#ifndef VW_JNI_BRIDGE_H
#define VW_JNI_BRIDGE_H

/*
 * vw_jni_bridge — JNI shim over vw_client_core/vw_vault (TASK-225).
 *
 * TASK-225 scope only: connect + login, enough to prove the whole toolchain
 * (Gradle -> NDK -> CMake -> mbedTLS/Argon2 FetchContent -> JNI -> Kotlin)
 * end-to-end against a real vapourwaultd before TASK-226 builds the full
 * bridge surface (file ops, sharing, version history, account
 * self-service) on top of it. Vault RPCs are TASK-230's job.
 *
 * Every exported function follows the standard JNI naming convention
 * (Java_<package>_<Class>_<method>) for the Kotlin object
 * com.vaporwault.client.VwNative — see VwNative.kt.
 */

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Connect to host:port and authenticate with username/password.
 *
 * ca_cert_pem_path: pass an empty string to use VW_CERT_VERIFY_NONE (test
 * only — see ARCHITECTURE.md's gateway precedent for why this must never be
 * the production default); a real path enables VW_CERT_VERIFY_REQUIRED.
 *
 * Returns an opaque, non-zero native session handle on success (an
 * vw_client_sess_t* cast to jlong), or 0 on failure — call
 * nativeLastError() to get the vw_err_t code. The caller (Kotlin) owns the
 * handle and must eventually pass it to nativeLogout().
 */
JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeConnect(
    JNIEnv *env, jobject thiz,
    jstring host, jint port, jstring ca_cert_pem_path,
    jstring username, jbyteArray password);

/* Returns the vw_err_t code from the most recent nativeConnect() call on
 * this thread (0 == VW_OK). */
JNIEXPORT jint JNICALL
Java_com_vaporwault_client_VwNative_nativeLastError(JNIEnv *env, jobject thiz);

/* Send AUTH_LOGOUT, close the TLS connection, and free the session. */
JNIEXPORT void JNICALL
Java_com_vaporwault_client_VwNative_nativeLogout(JNIEnv *env, jobject thiz,
                                                   jlong session_handle);

#ifdef __cplusplus
}
#endif

#endif /* VW_JNI_BRIDGE_H */
