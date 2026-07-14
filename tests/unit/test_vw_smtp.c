/*
 * test_vw_smtp.c — unit tests for the vw_smtp module.
 *
 * All tests exercise the public API (vw_smtp_validate_cfg and vw_smtp_send).
 * The internal smtp_no_crlf helper is tested indirectly through vw_smtp_send.
 *
 * TC-1: validate_cfg — NULL cfg → VW_ERR_INVALID_ARG.
 * TC-2: validate_cfg — empty host → VW_ERR_INVALID_ARG.
 * TC-3: validate_cfg — port == 0 → VW_ERR_INVALID_ARG.
 * TC-4: validate_cfg — tls_mode out of range → VW_ERR_INVALID_ARG.
 * TC-5: validate_cfg — verify_cert=1 with empty ca_cert_path → VW_ERR_INVALID_ARG.
 * TC-6: validate_cfg — fully valid config → VW_OK.
 * TC-7: smtp_send — NULL cfg → VW_ERR_INVALID_ARG (no connection attempted).
 * TC-8: smtp_send — to_addr contains CR → VW_ERR_INVALID_ARG.
 * TC-9: smtp_send — subject contains LF → VW_ERR_INVALID_ARG.
 * TC-10: smtp_send — connect to non-listening port → VW_ERR_NET_CONNECT.
 */

#include "vw_test.h"
#include "vw_smtp.h"
#include "vw_proto.h"

#include <string.h>

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Build a valid baseline config. Individual tests mutate specific fields. */
static vw_smtp_cfg_t make_valid_cfg(void) {
    vw_smtp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* strncpy-safe: all destination arrays are sized at field width */
    strncpy(cfg.host,      "mail.example.com",    sizeof(cfg.host) - 1);
    cfg.port       = 587;
    strncpy(cfg.username,  "testuser",             sizeof(cfg.username) - 1);
    strncpy(cfg.password,  "testpass",             sizeof(cfg.password) - 1);
    strncpy(cfg.from_addr, "sender@example.com",   sizeof(cfg.from_addr) - 1);
    strncpy(cfg.from_name, "Test Sender",           sizeof(cfg.from_name) - 1);
    cfg.tls_mode    = VW_SMTP_TLS_STARTTLS;
    cfg.verify_cert = 0;  /* no TLS peer auth — testing mode */
    cfg.ca_cert_path[0] = '\0';
    return cfg;
}

/* ── Test suite ──────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_smtp") {

    char err_msg[256];

    /* ── validate_cfg tests ───────────────────────────────────────────────── */

    VW_TEST_CASE("TC-1: validate_cfg NULL cfg → VW_ERR_INVALID_ARG") {
        vw_err_t err = vw_smtp_validate_cfg(NULL, NULL, 0);
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("TC-2: validate_cfg empty host → VW_ERR_INVALID_ARG") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        cfg.host[0] = '\0';
        err_msg[0] = '\0';
        vw_err_t err = vw_smtp_validate_cfg(&cfg, err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
        VW_ASSERT(err_msg[0] != '\0'); /* error message populated */
    }

    VW_TEST_CASE("TC-3: validate_cfg port == 0 → VW_ERR_INVALID_ARG") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        cfg.port = 0;
        err_msg[0] = '\0';
        vw_err_t err = vw_smtp_validate_cfg(&cfg, err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
        VW_ASSERT(err_msg[0] != '\0');
    }

    VW_TEST_CASE("TC-4: validate_cfg tls_mode out of range → VW_ERR_INVALID_ARG") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        cfg.tls_mode = (vw_smtp_tls_t)99;
        err_msg[0] = '\0';
        vw_err_t err = vw_smtp_validate_cfg(&cfg, err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
        VW_ASSERT(err_msg[0] != '\0');
    }

    VW_TEST_CASE("TC-5: validate_cfg verify_cert=1 + empty ca_cert_path → VW_ERR_INVALID_ARG") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        cfg.verify_cert    = 1;
        cfg.ca_cert_path[0] = '\0';
        err_msg[0] = '\0';
        vw_err_t err = vw_smtp_validate_cfg(&cfg, err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
        VW_ASSERT(err_msg[0] != '\0');
    }

    VW_TEST_CASE("TC-5b: validate_cfg verify_cert=1 + non-empty ca_cert_path → VW_OK") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        cfg.verify_cert = 1;
        strncpy(cfg.ca_cert_path, "/etc/ssl/ca.pem", sizeof(cfg.ca_cert_path) - 1);
        vw_err_t err = vw_smtp_validate_cfg(&cfg, NULL, 0);
        VW_ASSERT_ERR(err, VW_OK);
    }

    VW_TEST_CASE("TC-6: validate_cfg fully valid config → VW_OK") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        vw_err_t err = vw_smtp_validate_cfg(&cfg, err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_OK);
    }

    /* ── smtp_send tests ─────────────────────────────────────────────────── */

    VW_TEST_CASE("TC-7: smtp_send NULL cfg → VW_ERR_INVALID_ARG") {
        /* No connection is opened; the NULL check fires first. */
        vw_err_t err = vw_smtp_send(NULL,
                                     "to@example.com",
                                     "Subject",
                                     "Body",
                                     NULL, 0);
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("TC-7b: smtp_send NULL to_addr → VW_ERR_INVALID_ARG") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        vw_err_t err = vw_smtp_send(&cfg, NULL, "Subject", "Body", NULL, 0);
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("TC-8: smtp_send to_addr with CR → VW_ERR_INVALID_ARG (header injection blocked)") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        /* CR injection attempt in the To address */
        vw_err_t err = vw_smtp_send(&cfg,
                                     "evil\r\nBcc: spy@example.com\r\nX-Pad: x@example.com",
                                     "Subject",
                                     "Body",
                                     err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("TC-9: smtp_send subject with LF → VW_ERR_INVALID_ARG (header injection blocked)") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        /* LF injection attempt in the Subject header */
        vw_err_t err = vw_smtp_send(&cfg,
                                     "to@example.com",
                                     "Legitimate Subject\nX-Injected: evil",
                                     "Body",
                                     err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("TC-10: smtp_send to non-listening port → VW_ERR_NET_CONNECT") {
        vw_smtp_cfg_t cfg = make_valid_cfg();
        /* Point at 127.0.0.1:43780 — a port that is almost certainly not
         * listening; if by chance it is, the server will not speak SMTP and
         * the test may return VW_ERR_IO instead.  VW_ERR_NET_CONNECT is the
         * normal result. */
        strncpy(cfg.host, "127.0.0.1", sizeof(cfg.host) - 1);
        cfg.port     = 43780;
        cfg.tls_mode = VW_SMTP_TLS_NONE;

        vw_err_t err = vw_smtp_send(&cfg,
                                     "to@example.com",
                                     "Test",
                                     "Body",
                                     err_msg, sizeof(err_msg));
        VW_ASSERT_ERR(err, VW_ERR_NET_CONNECT);
    }
}

VW_TEST_SUITE_END()
