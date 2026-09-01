#include "vw_jni_bridge.h"

#include "vw_client_core.h"
#include "../core/vw_net.h"

#include <android/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "vw_jni_bridge"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * TASK-225 scope: single-call connect+login, so a simple thread-local error
 * slot is enough — TASK-226's full bridge surface will need a real
 * per-call result-passing convention once there's more than one outstanding
 * operation per thread to reason about.
 */
static _Thread_local vw_err_t g_last_error = VW_OK;

JNIEXPORT jlong JNICALL
Java_com_vaporwault_client_VwNative_nativeConnect(
    JNIEnv *env, jobject thiz,
    jstring host, jint port, jstring ca_cert_pem_path,
    jstring username, jbyteArray password)
{
    (void)thiz;

    const char *host_c = (*env)->GetStringUTFChars(env, host, NULL);
    const char *ca_path_c = (*env)->GetStringUTFChars(env, ca_cert_pem_path, NULL);
    const char *username_c = (*env)->GetStringUTFChars(env, username, NULL);
    jbyte *password_bytes = (*env)->GetByteArrayElements(env, password, NULL);
    jsize password_len = (*env)->GetArrayLength(env, password);

    vw_client_cfg_t cfg = {
        .host = host_c,
        .port = (uint16_t)port,
        .cert_verify = (ca_path_c[0] == '\0') ? VW_CERT_VERIFY_NONE
                                               : VW_CERT_VERIFY_REQUIRED,
        .ca_cert_pem_path = (ca_path_c[0] == '\0') ? NULL : ca_path_c,
        .conn_opts = NULL,
    };

    vw_client_sess_t *sess = NULL;
    vw_err_t rc = vw_client_connect(&cfg,
                                     username_c, (uint16_t)strlen(username_c),
                                     password_bytes, (size_t)password_len,
                                     NULL, NULL,
                                     &sess);

    (*env)->ReleaseStringUTFChars(env, host, host_c);
    (*env)->ReleaseStringUTFChars(env, ca_cert_pem_path, ca_path_c);
    (*env)->ReleaseStringUTFChars(env, username, username_c);
    (*env)->ReleaseByteArrayElements(env, password, password_bytes, JNI_ABORT);

    g_last_error = rc;

    if (rc != VW_OK) {
        LOGE("vw_client_connect failed: err=%d", (int)rc);
        return 0;
    }

    return (jlong)(intptr_t)sess;
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
