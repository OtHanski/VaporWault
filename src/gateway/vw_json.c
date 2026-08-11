#include "vw_json.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Decoding: iterative scanning, never recursive (see header doc) ────────── */

static void skip_ws(const char *p, size_t len, size_t *i) {
    while (*i < len && (p[*i] == ' ' || p[*i] == '\t' || p[*i] == '\n' || p[*i] == '\r')) {
        (*i)++;
    }
}

/*
 * Advances *i past one JSON string literal starting at p[*i] == '"'.
 * On success *i points just past the closing quote; out_start and
 * out_len (either may be NULL) describe the still-escaped content between
 * the quotes.
 */
static vw_err_t skip_string(const char *p, size_t len, size_t *i,
                             const char **out_start, size_t *out_len) {
    if (*i >= len || p[*i] != '"') return VW_ERR_PROTO_INVALID;
    (*i)++;
    size_t start = *i;
    while (*i < len && p[*i] != '"') {
        if (p[*i] == '\\') {
            (*i)++;
            if (*i >= len) return VW_ERR_PROTO_INVALID;
        }
        (*i)++;
    }
    if (*i >= len) return VW_ERR_PROTO_INVALID;
    if (out_start) *out_start = p + start;
    if (out_len) *out_len = *i - start;
    (*i)++; /* closing quote */
    return VW_OK;
}

/*
 * Advances *i past one JSON value starting at p[*i] (after skipping
 * leading whitespace). object/array nesting is skipped via a depth
 * counter over the SAME bracket type the value opened with — strings
 * inside are skipped via skip_string so quoted braces/brackets never
 * confuse the counter, and a differently-typed bracket nested inside
 * (e.g. '[' while counting '{'...'}') is treated as an ordinary character,
 * which is safe because valid JSON guarantees each bracket type is
 * independently balanced. No recursive function calls at any nesting depth.
 */
static vw_err_t skip_value(const char *p, size_t len, size_t *i,
                            vw_json_kind_t *out_kind,
                            const char **out_start, size_t *out_len) {
    skip_ws(p, len, i);
    if (*i >= len) return VW_ERR_PROTO_INVALID;

    size_t start = *i;
    char c = p[*i];

    if (c == '"') {
        const char *s = NULL;
        size_t l = 0;
        vw_err_t err = skip_string(p, len, i, &s, &l);
        if (err != VW_OK) return err;
        if (out_kind) *out_kind = VW_JSON_STRING;
        if (out_start) *out_start = s;
        if (out_len) *out_len = l;
        return VW_OK;
    }

    if (c == '{' || c == '[') {
        char open = c;
        char close = (c == '{') ? '}' : ']';
        int depth = 0;
        while (*i < len) {
            char cc = p[*i];
            if (cc == '"') {
                vw_err_t err = skip_string(p, len, i, NULL, NULL);
                if (err != VW_OK) return err;
                continue;
            }
            if (cc == open) {
                depth++;
                (*i)++;
                continue;
            }
            if (cc == close) {
                depth--;
                (*i)++;
                if (depth == 0) break;
                continue;
            }
            (*i)++;
        }
        if (depth != 0) return VW_ERR_PROTO_INVALID;
        if (out_kind) *out_kind = (c == '{') ? VW_JSON_OBJECT : VW_JSON_ARRAY;
        if (out_start) *out_start = p + start;
        if (out_len) *out_len = *i - start;
        return VW_OK;
    }

    if (c == 't' || c == 'f') {
        int is_true = (c == 't');
        const char *lit = is_true ? "true" : "false";
        size_t lit_len = is_true ? 4u : 5u;
        if (*i + lit_len > len || memcmp(p + *i, lit, lit_len) != 0) return VW_ERR_PROTO_INVALID;
        *i += lit_len;
        if (out_kind) *out_kind = VW_JSON_BOOL;
        if (out_start) *out_start = p + start;
        if (out_len) *out_len = lit_len;
        return VW_OK;
    }

    if (c == 'n') {
        if (*i + 4 > len || memcmp(p + *i, "null", 4) != 0) return VW_ERR_PROTO_INVALID;
        *i += 4;
        if (out_kind) *out_kind = VW_JSON_NULL;
        if (out_start) *out_start = p + start;
        if (out_len) *out_len = 4;
        return VW_OK;
    }

    if (c == '-' || (c >= '0' && c <= '9')) {
        if (c == '-') (*i)++;
        if (*i >= len || p[*i] < '0' || p[*i] > '9') return VW_ERR_PROTO_INVALID;
        while (*i < len && p[*i] >= '0' && p[*i] <= '9') (*i)++;
        if (*i < len && p[*i] == '.') {
            (*i)++;
            if (*i >= len || p[*i] < '0' || p[*i] > '9') return VW_ERR_PROTO_INVALID;
            while (*i < len && p[*i] >= '0' && p[*i] <= '9') (*i)++;
        }
        if (*i < len && (p[*i] == 'e' || p[*i] == 'E')) {
            (*i)++;
            if (*i < len && (p[*i] == '+' || p[*i] == '-')) (*i)++;
            if (*i >= len || p[*i] < '0' || p[*i] > '9') return VW_ERR_PROTO_INVALID;
            while (*i < len && p[*i] >= '0' && p[*i] <= '9') (*i)++;
        }
        if (out_kind) *out_kind = VW_JSON_NUMBER;
        if (out_start) *out_start = p + start;
        if (out_len) *out_len = *i - start;
        return VW_OK;
    }

    return VW_ERR_PROTO_INVALID;
}

/* Parses a NUMBER span as a plain integer; rejects '.'/'e'/'E' (this
 * module's scope is integers only, per TASK-130). */
static vw_err_t number_span_to_int(const char *start, size_t len, int64_t *out) {
    if (len == 0 || len >= 32) return VW_ERR_PROTO_INVALID;
    for (size_t k = 0; k < len; k++) {
        if (start[k] == '.' || start[k] == 'e' || start[k] == 'E') return VW_ERR_PROTO_INVALID;
    }
    char tmp[32];
    memcpy(tmp, start, len);
    tmp[len] = '\0';
    char *endptr = NULL;
    *out = strtoll(tmp, &endptr, 10);
    if (endptr == tmp) return VW_ERR_PROTO_INVALID;
    return VW_OK;
}

vw_err_t vw_json_object_get(const char *obj, size_t obj_len,
                             const char *key, vw_json_value_t *out) {
    if (obj == NULL || key == NULL || out == NULL) return VW_ERR_INVALID_ARG;

    size_t i = 0;
    skip_ws(obj, obj_len, &i);
    if (i >= obj_len || obj[i] != '{') return VW_ERR_PROTO_INVALID;
    i++;
    skip_ws(obj, obj_len, &i);
    if (i < obj_len && obj[i] == '}') return VW_ERR_NOT_FOUND; /* empty object */

    size_t key_len = strlen(key);

    for (;;) {
        skip_ws(obj, obj_len, &i);
        const char *k_start = NULL;
        size_t k_len = 0;
        vw_err_t err = skip_string(obj, obj_len, &i, &k_start, &k_len);
        if (err != VW_OK) return err;

        skip_ws(obj, obj_len, &i);
        if (i >= obj_len || obj[i] != ':') return VW_ERR_PROTO_INVALID;
        i++;

        vw_json_kind_t kind;
        const char *v_start = NULL;
        size_t v_len = 0;
        err = skip_value(obj, obj_len, &i, &kind, &v_start, &v_len);
        if (err != VW_OK) return err;

        if (k_len == key_len && memcmp(k_start, key, key_len) == 0) {
            memset(out, 0, sizeof(*out));
            out->kind = kind;
            out->start = v_start;
            out->len = v_len;
            if (kind == VW_JSON_BOOL) {
                out->bool_val = (v_len == 4); /* "true" (4) vs "false" (5) */
            } else if (kind == VW_JSON_NUMBER) {
                err = number_span_to_int(v_start, v_len, &out->number_val);
                if (err != VW_OK) return err;
            }
            return VW_OK;
        }

        skip_ws(obj, obj_len, &i);
        if (i < obj_len && obj[i] == ',') {
            i++;
            continue;
        }
        if (i < obj_len && obj[i] == '}') return VW_ERR_NOT_FOUND;
        return VW_ERR_PROTO_INVALID;
    }
}

vw_err_t vw_json_array_foreach(const char *arr, size_t arr_len,
                                vw_json_array_cb_t cb, void *userdata) {
    if (arr == NULL || cb == NULL) return VW_ERR_INVALID_ARG;

    size_t i = 0;
    skip_ws(arr, arr_len, &i);
    if (i >= arr_len || arr[i] != '[') return VW_ERR_PROTO_INVALID;
    i++;
    skip_ws(arr, arr_len, &i);
    if (i < arr_len && arr[i] == ']') return VW_OK; /* empty array */

    for (;;) {
        vw_json_kind_t kind;
        const char *v_start = NULL;
        size_t v_len = 0;
        vw_err_t err = skip_value(arr, arr_len, &i, &kind, &v_start, &v_len);
        if (err != VW_OK) return err;

        vw_json_value_t element;
        memset(&element, 0, sizeof(element));
        element.kind = kind;
        element.start = v_start;
        element.len = v_len;
        if (kind == VW_JSON_BOOL) {
            element.bool_val = (v_len == 4);
        } else if (kind == VW_JSON_NUMBER) {
            err = number_span_to_int(v_start, v_len, &element.number_val);
            if (err != VW_OK) return err;
        }

        if (cb(userdata, element) != 0) return VW_OK; /* caller stopped early */

        skip_ws(arr, arr_len, &i);
        if (i < arr_len && arr[i] == ',') {
            i++;
            continue;
        }
        if (i < arr_len && arr[i] == ']') return VW_OK;
        return VW_ERR_PROTO_INVALID;
    }
}

vw_err_t vw_json_string_decode(const char *escaped, size_t escaped_len,
                                char *out_buf, size_t out_buf_size,
                                size_t *out_len) {
    if (escaped == NULL || out_buf == NULL || out_buf_size == 0) return VW_ERR_INVALID_ARG;

    size_t oi = 0;
    for (size_t i = 0; i < escaped_len; i++) {
        char c = escaped[i];
        if (c != '\\') {
            if (oi + 1 >= out_buf_size) return VW_ERR_PROTO_TOO_LARGE;
            out_buf[oi++] = c;
            continue;
        }

        i++;
        if (i >= escaped_len) return VW_ERR_PROTO_INVALID;
        char e = escaped[i];

        if (e == 'u') {
            if (i + 4 >= escaped_len) return VW_ERR_PROTO_INVALID;
            unsigned cp = 0;
            for (int k = 1; k <= 4; k++) {
                char h = escaped[i + (size_t)k];
                cp <<= 4;
                if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                else return VW_ERR_PROTO_INVALID;
            }
            i += 4;

            uint32_t codepoint = cp;
            if (cp >= 0xD800u && cp <= 0xDBFFu) {
                if (i + 6 >= escaped_len || escaped[i + 1] != '\\' || escaped[i + 2] != 'u') {
                    return VW_ERR_PROTO_INVALID;
                }
                unsigned lo = 0;
                for (int k = 3; k <= 6; k++) {
                    char h = escaped[i + (size_t)k];
                    lo <<= 4;
                    if (h >= '0' && h <= '9') lo |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') lo |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') lo |= (unsigned)(h - 'A' + 10);
                    else return VW_ERR_PROTO_INVALID;
                }
                if (lo < 0xDC00u || lo > 0xDFFFu) return VW_ERR_PROTO_INVALID;
                i += 6;
                codepoint = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
            }

            unsigned char utf8[4];
            size_t utf8_len;
            if (codepoint <= 0x7Fu) {
                utf8[0] = (unsigned char)codepoint;
                utf8_len = 1;
            } else if (codepoint <= 0x7FFu) {
                utf8[0] = (unsigned char)(0xC0u | (codepoint >> 6));
                utf8[1] = (unsigned char)(0x80u | (codepoint & 0x3Fu));
                utf8_len = 2;
            } else if (codepoint <= 0xFFFFu) {
                utf8[0] = (unsigned char)(0xE0u | (codepoint >> 12));
                utf8[1] = (unsigned char)(0x80u | ((codepoint >> 6) & 0x3Fu));
                utf8[2] = (unsigned char)(0x80u | (codepoint & 0x3Fu));
                utf8_len = 3;
            } else {
                utf8[0] = (unsigned char)(0xF0u | (codepoint >> 18));
                utf8[1] = (unsigned char)(0x80u | ((codepoint >> 12) & 0x3Fu));
                utf8[2] = (unsigned char)(0x80u | ((codepoint >> 6) & 0x3Fu));
                utf8[3] = (unsigned char)(0x80u | (codepoint & 0x3Fu));
                utf8_len = 4;
            }

            if (oi + utf8_len >= out_buf_size) return VW_ERR_PROTO_TOO_LARGE;
            memcpy(out_buf + oi, utf8, utf8_len);
            oi += utf8_len;
            continue;
        }

        char decoded;
        switch (e) {
            case '"':  decoded = '"';  break;
            case '\\': decoded = '\\'; break;
            case '/':  decoded = '/';  break;
            case 'b':  decoded = '\b'; break;
            case 'f':  decoded = '\f'; break;
            case 'n':  decoded = '\n'; break;
            case 'r':  decoded = '\r'; break;
            case 't':  decoded = '\t'; break;
            default:   return VW_ERR_PROTO_INVALID;
        }
        if (oi + 1 >= out_buf_size) return VW_ERR_PROTO_TOO_LARGE;
        out_buf[oi++] = decoded;
    }

    out_buf[oi] = '\0';
    if (out_len) *out_len = oi;
    return VW_OK;
}

/* ── Encoding ─────────────────────────────────────────────────────────────── */

void vw_json_writer_init(vw_json_writer_t *w, char *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->error = 0;
    w->need_comma = 0;
    if (cap > 0) buf[0] = '\0';
}

static void writer_put(vw_json_writer_t *w, const char *s, size_t n) {
    if (w->error) return;
    if (w->len + n >= w->cap) {
        w->error = 1;
        return;
    }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
    w->buf[w->len] = '\0';
}

static void writer_putc(vw_json_writer_t *w, char c) {
    writer_put(w, &c, 1);
}

static void writer_maybe_comma(vw_json_writer_t *w) {
    if (w->need_comma) writer_putc(w, ',');
}

vw_err_t vw_json_writer_result(const vw_json_writer_t *w, size_t *out_len) {
    if (w->error) return VW_ERR_PROTO_TOO_LARGE;
    if (out_len) *out_len = w->len;
    return VW_OK;
}

void vw_json_write_object_start(vw_json_writer_t *w) {
    writer_maybe_comma(w);
    writer_putc(w, '{');
    w->need_comma = 0;
}

void vw_json_write_object_end(vw_json_writer_t *w) {
    writer_putc(w, '}');
    w->need_comma = 1;
}

void vw_json_write_array_start(vw_json_writer_t *w) {
    writer_maybe_comma(w);
    writer_putc(w, '[');
    w->need_comma = 0;
}

void vw_json_write_array_end(vw_json_writer_t *w) {
    writer_putc(w, ']');
    w->need_comma = 1;
}

void vw_json_write_key(vw_json_writer_t *w, const char *key) {
    writer_maybe_comma(w);
    writer_putc(w, '"');
    writer_put(w, key, strlen(key));
    writer_put(w, "\":", 2);
    w->need_comma = 0; /* the value follows immediately; no comma before it */
}

void vw_json_write_string(vw_json_writer_t *w, const char *str, size_t str_len) {
    writer_maybe_comma(w);
    writer_putc(w, '"');
    for (size_t i = 0; i < str_len; i++) {
        unsigned char c = (unsigned char)str[i];
        switch (c) {
            case '"':  writer_put(w, "\\\"", 2); break;
            case '\\': writer_put(w, "\\\\", 2); break;
            case '\b': writer_put(w, "\\b", 2); break;
            case '\f': writer_put(w, "\\f", 2); break;
            case '\n': writer_put(w, "\\n", 2); break;
            case '\r': writer_put(w, "\\r", 2); break;
            case '\t': writer_put(w, "\\t", 2); break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    int n = snprintf(esc, sizeof(esc), "\\u%04x", c);
                    if (n > 0) writer_put(w, esc, (size_t)n);
                } else {
                    writer_putc(w, (char)c);
                }
        }
    }
    writer_putc(w, '"');
    w->need_comma = 1;
}

void vw_json_write_int(vw_json_writer_t *w, int64_t v) {
    writer_maybe_comma(w);
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
    if (n > 0) writer_put(w, tmp, (size_t)n);
    w->need_comma = 1;
}

void vw_json_write_uint(vw_json_writer_t *w, uint64_t v) {
    writer_maybe_comma(w);
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
    if (n > 0) writer_put(w, tmp, (size_t)n);
    w->need_comma = 1;
}

void vw_json_write_bool(vw_json_writer_t *w, int v) {
    writer_maybe_comma(w);
    if (v) writer_put(w, "true", 4);
    else writer_put(w, "false", 5);
    w->need_comma = 1;
}

void vw_json_write_null(vw_json_writer_t *w) {
    writer_maybe_comma(w);
    writer_put(w, "null", 4);
    w->need_comma = 1;
}
