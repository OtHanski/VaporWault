#include "vw_update_manifest.h"
#include "vw_update_net.h"
#include "../core/vw_crypto.h"
#include "../core/vw_update_pubkey.h"
#include "../core/vw_fs.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Fixed, well-known GitHub Releases location — see ARCHITECTURE.md's
 * "Client auto-update: trust model" row for why this is the stable
 * `releases/latest/download/...` alias rather than the general
 * api.github.com REST API (avoids auth, rate limits, and a general JSON
 * API surface).
 *
 * Overridable via target_compile_definitions (same convention as
 * vw_update_net.c's timeout constants) so tests can point this pipeline
 * at a local test server instead of the real github.com — production
 * code never overrides these. VW_UPDATE_PORT is similarly test-only
 * (production always uses 443, matching vw_update_https_get's real
 * production callers, which never pass anything else). */
#ifndef VW_UPDATE_GITHUB_HOST
#define VW_UPDATE_GITHUB_HOST      "github.com"
#endif
#ifndef VW_UPDATE_PORT
#define VW_UPDATE_PORT             443u
#endif
#ifndef VW_UPDATE_MANIFEST_PATH
#define VW_UPDATE_MANIFEST_PATH    "/OtHanski/VaporWault/releases/latest/download/update-manifest.json"
#endif
#ifndef VW_UPDATE_MANIFEST_SIG_PATH
#define VW_UPDATE_MANIFEST_SIG_PATH "/OtHanski/VaporWault/releases/latest/download/update-manifest.json.sig"
#endif

#define VW_UPDATE_MANIFEST_MAX_BYTES  (64u * 1024u)  /* generous for a ~6-field, few-asset JSON doc */
#define VW_UPDATE_SIG_MAX_BYTES       512u           /* a DER ECDSA P-256 sig is ~70-72 bytes */

/* daemon.conf's own key=value format (src/client/vw_daemon.c) is
 * deliberately NOT reused via a shared struct/API here — vw_daemon.c's
 * vw_daemon_cfg_t is private to that module (same module-boundary
 * discipline vw_vault.c's own header comment documents for
 * vw_store_files.h). This does its own minimal, self-contained
 * read/rewrite of exactly one key, preserving every other line in the
 * file untouched. "daemon.conf" is the same filename vw_daemon.c's
 * CONFIG_FILE constant names — duplicated as a literal since there is no
 * shared public header for it. */
#define VW_UPDATE_DAEMON_CONF_NAME     "daemon.conf"
#define VW_UPDATE_SEQUENCE_KEY         "update_last_seen_sequence"

/* ── Rollback-ratchet persistence ────────────────────────────────────────── */

static vw_err_t read_update_sequence(const char *state_dir, uint64_t *out) {
    *out = 0; /* absent == "never seen a manifest" */

    char path[600];
    int n = snprintf(path, sizeof(path), "%s/%s", state_dir, VW_UPDATE_DAEMON_CONF_NAME);
    if (n <= 0 || (size_t)n >= sizeof(path)) return VW_ERR_INVALID_ARG;

    void *buf = NULL;
    size_t len = 0;
    if (vw_fs_read_file(path, &buf, &len) != VW_OK)
        return VW_OK; /* no config file yet — ratchet starts at 0 */

    const char *p = (const char *)buf;
    const char *end = p + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;
        size_t line_len = (size_t)(line_end - p);

        static const char key[] = VW_UPDATE_SEQUENCE_KEY;
        size_t key_len = sizeof(key) - 1;
        if (line_len > key_len && strncmp(p, key, key_len) == 0) {
            const char *rest = p + key_len;
            const char *rest_end = line_end;
            while (rest < rest_end && (*rest == ' ' || *rest == '\t')) rest++;
            if (rest < rest_end && *rest == '=') {
                rest++;
                while (rest < rest_end && (*rest == ' ' || *rest == '\t')) rest++;
                char numbuf[32];
                size_t vlen = (size_t)(rest_end - rest);
                /* Trim a trailing \r left by CRLF line endings. */
                if (vlen > 0 && rest[vlen - 1] == '\r') vlen--;
                if (vlen > 0 && vlen < sizeof(numbuf)) {
                    memcpy(numbuf, rest, vlen);
                    numbuf[vlen] = '\0';
                    *out = strtoull(numbuf, NULL, 10);
                }
            }
        }
        p = nl ? nl + 1 : end;
    }

    free(buf);
    return VW_OK;
}

/* Rewrites daemon.conf with VW_UPDATE_SEQUENCE_KEY set to value,
 * preserving every other line verbatim (replacing an existing
 * update_last_seen_sequence line in place if present, appending a new one
 * otherwise). Uses vw_fs_atomic_write so a crash mid-write can never leave
 * daemon.conf truncated/corrupted — stronger durability than
 * vw_daemon.c's own plain fopen("w") writer for its own keys, but that's
 * an existing, separate concern this task doesn't touch. */
static vw_err_t write_update_sequence(const char *state_dir, uint64_t value) {
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/%s", state_dir, VW_UPDATE_DAEMON_CONF_NAME);
    if (n <= 0 || (size_t)n >= sizeof(path)) return VW_ERR_INVALID_ARG;

    void *buf = NULL;
    size_t len = 0;
    int had_file = (vw_fs_read_file(path, &buf, &len) == VW_OK);

    /* Build the new file contents in a growable buffer: every existing
     * line except a prior update_last_seen_sequence one, then the new
     * value appended at the end. */
    size_t out_cap = len + 128;
    char *out = (char *)malloc(out_cap);
    if (!out) { free(buf); return VW_ERR_OOM; }
    size_t out_len = 0;
    int replaced = 0;

    static const char key[] = VW_UPDATE_SEQUENCE_KEY;
    size_t key_len = sizeof(key) - 1;

    if (had_file) {
        const char *p = (const char *)buf;
        const char *end = p + len;
        while (p < end) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            const char *line_end = nl ? nl + 1 : end; /* include the \n if present */
            size_t chunk_len = (size_t)(line_end - p);
            size_t bare_len = nl ? (size_t)(nl - p) : chunk_len;

            int is_seq_line = (bare_len > key_len && strncmp(p, key, key_len) == 0);

            if (!is_seq_line) {
                if (out_len + chunk_len > out_cap) {
                    out_cap = (out_len + chunk_len) * 2;
                    char *grown = (char *)realloc(out, out_cap);
                    if (!grown) { free(out); free(buf); return VW_ERR_OOM; }
                    out = grown;
                }
                memcpy(out + out_len, p, chunk_len);
                out_len += chunk_len;
            } else {
                replaced = 1; /* drop this line; the fresh one is appended below */
            }
            p = line_end;
        }
    }
    free(buf);

    char seq_line[96];
    int sn = snprintf(seq_line, sizeof(seq_line), "%s = %llu\n",
                       VW_UPDATE_SEQUENCE_KEY, (unsigned long long)value);
    if (sn <= 0 || (size_t)sn >= sizeof(seq_line)) { free(out); return VW_ERR_INVALID_ARG; }

    if (out_len + (size_t)sn > out_cap) {
        out_cap = out_len + (size_t)sn;
        char *grown = (char *)realloc(out, out_cap);
        if (!grown) { free(out); return VW_ERR_OOM; }
        out = grown;
    }
    memcpy(out + out_len, seq_line, (size_t)sn);
    out_len += (size_t)sn;
    (void)replaced; /* only affects whether the line moved to the end; both
                        outcomes are correct, kept for readability/debugging */

    vw_err_t err = vw_fs_atomic_write(path, out, out_len);
    free(out);
    return err;
}

/* ── Minimal JSON parsing (scoped to this manifest's fixed 6-field schema,
 * NOT a general JSON library — see ARCHITECTURE.md's "Client auto-update:
 * manifest parser" row for why vw_json.c is deliberately not reused here).
 * Keys may appear in any order within an object (not assumed fixed-order,
 * even though this project's own CI generator emits a fixed order) — this
 * costs little extra code and avoids coupling the parser to the
 * generator's exact field order. ───────────────────────────────────────── */

typedef struct {
    const char *p;
    const char *end;
} jcur_t;

static void jskip_ws(jcur_t *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
        c->p++;
}

static vw_err_t jexpect(jcur_t *c, char ch) {
    jskip_ws(c);
    if (c->p >= c->end || *c->p != ch) return VW_ERR_UPDATE_MANIFEST_INVALID;
    c->p++;
    return VW_OK;
}

/* Peeks (after skipping whitespace) without consuming. */
static int jpeek(jcur_t *c, char ch) {
    jcur_t tmp = *c;
    jskip_ws(&tmp);
    return tmp.p < tmp.end && *tmp.p == ch;
}

static vw_err_t jparse_string(jcur_t *c, char *out, size_t out_cap) {
    vw_err_t err = jexpect(c, '"');
    if (err != VW_OK) return err;

    size_t n = 0;
    while (c->p < c->end && *c->p != '"') {
        char ch = *c->p;
        if (ch == '\\') {
            c->p++;
            if (c->p >= c->end) return VW_ERR_UPDATE_MANIFEST_INVALID;
            char esc = *c->p;
            /* Only the escapes this project's own generator could ever
             * plausibly emit for these fields (filenames, version
             * strings, hex hashes — all plain ASCII, no control chars,
             * no literal quotes/backslashes expected in practice, but
             * handle the structurally-valid escapes for them anyway). No
             * \u support — never needed for this schema, and one less
             * class of parser complexity to get right under adversarial
             * input. */
            if (esc == '"' || esc == '\\' || esc == '/') ch = esc;
            else return VW_ERR_UPDATE_MANIFEST_INVALID;
        } else if ((unsigned char)ch < 0x20) {
            return VW_ERR_UPDATE_MANIFEST_INVALID; /* raw control byte in a string: reject */
        }
        if (n + 1 >= out_cap) return VW_ERR_UPDATE_MANIFEST_INVALID; /* too long for this field */
        out[n++] = ch;
        c->p++;
    }
    if (c->p >= c->end) return VW_ERR_UPDATE_MANIFEST_INVALID; /* unterminated string */
    c->p++; /* closing quote */
    out[n] = '\0';
    return VW_OK;
}

static vw_err_t jparse_uint(jcur_t *c, uint64_t *out) {
    jskip_ws(c);
    if (c->p >= c->end || *c->p < '0' || *c->p > '9') return VW_ERR_UPDATE_MANIFEST_INVALID;
    uint64_t v = 0;
    int ndigits = 0;
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        if (ndigits >= 19) return VW_ERR_UPDATE_MANIFEST_INVALID; /* overflow guard */
        v = v * 10 + (uint64_t)(*c->p - '0');
        c->p++; ndigits++;
    }
    *out = v;
    return VW_OK;
}

static vw_err_t jparse_asset(jcur_t *c, vw_update_manifest_asset_t *a) {
    memset(a, 0, sizeof(*a));
    int have_sha256 = 0;

    vw_err_t err = jexpect(c, '{');
    if (err != VW_OK) return err;

    if (jpeek(c, '}')) { c->p++; return VW_ERR_UPDATE_MANIFEST_INVALID; /* no empty assets */ }

    for (;;) {
        char key[32];
        err = jparse_string(c, key, sizeof(key));
        if (err != VW_OK) return err;
        err = jexpect(c, ':');
        if (err != VW_OK) return err;

        if (strcmp(key, "platform") == 0) {
            err = jparse_string(c, a->platform, sizeof(a->platform));
        } else if (strcmp(key, "arch") == 0) {
            err = jparse_string(c, a->arch, sizeof(a->arch));
        } else if (strcmp(key, "dist_kind") == 0) {
            err = jparse_string(c, a->dist_kind, sizeof(a->dist_kind));
        } else if (strcmp(key, "filename") == 0) {
            err = jparse_string(c, a->filename, sizeof(a->filename));
        } else if (strcmp(key, "sha256") == 0) {
            char hex[65];
            err = jparse_string(c, hex, sizeof(hex));
            if (err == VW_OK) {
                if (strlen(hex) != 64) return VW_ERR_UPDATE_MANIFEST_INVALID;
                err = vw_crypto_hex_decode(hex, 64, a->sha256);
                if (err == VW_OK) have_sha256 = 1;
            }
        } else {
            return VW_ERR_UPDATE_MANIFEST_INVALID; /* unknown asset field — reject, don't ignore */
        }
        if (err != VW_OK) return err;

        jskip_ws(c);
        if (c->p < c->end && *c->p == ',') { c->p++; continue; }
        break;
    }

    err = jexpect(c, '}');
    if (err != VW_OK) return err;

    if (a->platform[0] == '\0' || a->filename[0] == '\0' || !have_sha256)
        return VW_ERR_UPDATE_MANIFEST_INVALID; /* required fields missing */
    return VW_OK;
}

vw_err_t vw_update_manifest_parse(const char *data, size_t len, vw_update_manifest_t *out) {
    if (!out) return VW_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (!data) return VW_ERR_INVALID_ARG;
    jcur_t c = { data, data + len };

    vw_err_t err = jexpect(&c, '{');
    if (err != VW_OK) return err;

    int have_schema_version = 0, have_sequence = 0, have_release_version = 0,
        have_min_proto = 0, have_assets = 0;

    if (!jpeek(&c, '}')) {
        for (;;) {
            char key[40];
            err = jparse_string(&c, key, sizeof(key));
            if (err != VW_OK) return err;
            err = jexpect(&c, ':');
            if (err != VW_OK) return err;

            if (strcmp(key, "schema_version") == 0) {
                uint64_t v;
                err = jparse_uint(&c, &v);
                if (err == VW_OK) { out->schema_version = (uint32_t)v; have_schema_version = 1; }
            } else if (strcmp(key, "sequence") == 0) {
                err = jparse_uint(&c, &out->sequence);
                if (err == VW_OK) have_sequence = 1;
            } else if (strcmp(key, "release_version") == 0) {
                err = jparse_string(&c, out->release_version, sizeof(out->release_version));
                if (err == VW_OK) have_release_version = 1;
            } else if (strcmp(key, "min_client_protocol_version") == 0) {
                uint64_t v;
                err = jparse_uint(&c, &v);
                if (err == VW_OK) {
                    if (v > 0xFFFFu) return VW_ERR_UPDATE_MANIFEST_INVALID;
                    out->min_client_protocol_version = (uint16_t)v;
                    have_min_proto = 1;
                }
            } else if (strcmp(key, "published_at") == 0) {
                uint64_t v;
                err = jparse_uint(&c, &v);
                if (err == VW_OK) out->published_at = (int64_t)v; /* informational only */
            } else if (strcmp(key, "assets") == 0) {
                err = jexpect(&c, '[');
                if (err != VW_OK) return err;
                if (!jpeek(&c, ']')) {
                    for (;;) {
                        if (out->asset_count >= VW_UPDATE_MANIFEST_MAX_ASSETS)
                            return VW_ERR_UPDATE_MANIFEST_INVALID;
                        err = jparse_asset(&c, &out->assets[out->asset_count]);
                        if (err != VW_OK) return err;
                        out->asset_count++;
                        jskip_ws(&c);
                        if (c.p < c.end && *c.p == ',') { c.p++; continue; }
                        break;
                    }
                }
                err = jexpect(&c, ']');
                if (err == VW_OK) have_assets = (out->asset_count > 0);
            } else {
                return VW_ERR_UPDATE_MANIFEST_INVALID; /* unknown top-level field — reject */
            }
            if (err != VW_OK) return err;

            jskip_ws(&c);
            if (c.p < c.end && *c.p == ',') { c.p++; continue; }
            break;
        }
    }

    err = jexpect(&c, '}');
    if (err != VW_OK) return err;

    if (!have_schema_version || !have_sequence || !have_release_version ||
        !have_min_proto || !have_assets)
        return VW_ERR_UPDATE_MANIFEST_INVALID;
    if (out->schema_version != 1)
        return VW_ERR_UPDATE_MANIFEST_INVALID; /* unknown schema — fail closed, don't guess */

    return VW_OK;
}

/* ── Public entry point ──────────────────────────────────────────────────── */

vw_err_t vw_update_manifest_fetch_and_verify(const char *state_dir,
                                              vw_update_manifest_t *out) {
    if (!state_dir || !out) return VW_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    vw_update_response_t manifest_resp;
    memset(&manifest_resp, 0, sizeof(manifest_resp));
    vw_err_t err = vw_update_https_get(VW_UPDATE_GITHUB_HOST, (uint16_t)VW_UPDATE_PORT,
                                        VW_UPDATE_MANIFEST_PATH,
                                        VW_UPDATE_MANIFEST_MAX_BYTES, &manifest_resp);
    if (err != VW_OK) return VW_ERR_UPDATE_NET;

    vw_update_response_t sig_resp;
    memset(&sig_resp, 0, sizeof(sig_resp));
    err = vw_update_https_get(VW_UPDATE_GITHUB_HOST, (uint16_t)VW_UPDATE_PORT,
                               VW_UPDATE_MANIFEST_SIG_PATH,
                               VW_UPDATE_SIG_MAX_BYTES, &sig_resp);
    if (err != VW_OK) { vw_update_response_free(&manifest_resp); return VW_ERR_UPDATE_NET; }

    /* Mandatory order: verify the signature over the raw fetched bytes
     * BEFORE any JSON parsing ever runs. */
    uint8_t hash[VW_HASH_BYTES];
    err = vw_crypto_sha256(manifest_resp.body, manifest_resp.body_len, hash);
    if (err != VW_OK) {
        vw_update_response_free(&manifest_resp);
        vw_update_response_free(&sig_resp);
        return VW_ERR_UPDATE_MANIFEST_INVALID;
    }

    err = vw_crypto_ecdsa_p256_verify(VW_UPDATE_MANIFEST_PUBKEY, hash,
                                       sig_resp.body, sig_resp.body_len);
    vw_update_response_free(&sig_resp);
    if (err != VW_OK) {
        vw_update_response_free(&manifest_resp);
        return VW_ERR_UPDATE_MANIFEST_INVALID; /* fail closed */
    }

    vw_update_manifest_t parsed;
    err = vw_update_manifest_parse((const char *)manifest_resp.body, manifest_resp.body_len, &parsed);
    vw_update_response_free(&manifest_resp);
    if (err != VW_OK) return VW_ERR_UPDATE_MANIFEST_INVALID;

    uint64_t last_seen = 0;
    (void)read_update_sequence(state_dir, &last_seen); /* best-effort; absence == 0 */
    if (parsed.sequence < last_seen)
        return VW_ERR_UPDATE_MANIFEST_ROLLBACK; /* ratchet NOT advanced */

    err = write_update_sequence(state_dir, parsed.sequence);
    if (err != VW_OK) return err;

    *out = parsed;
    return VW_OK;
}
