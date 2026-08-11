#ifndef VW_JSON_H
#define VW_JSON_H

/*
 * vw_json — minimal JSON encode/decode for vapourwault-web-gateway
 * (TASK-130).
 *
 * Hand-rolled rather than vendored, per ARCHITECTURE.md's Gateway HTTP/JSON
 * layer decision: the gateway's request/response shapes are all fixed and
 * known ahead of time, so a general-purpose JSON library/DOM is more than
 * the requirement.
 *
 * Decoding never recurses: object/array nesting is skipped via an
 * iterative bracket-depth counter (see vw_json.c's skip_value), not
 * recursive-descent function calls, so a deeply-nested attacker-controlled
 * payload cannot grow the C call stack. A caller that wants to look inside
 * a nested ARRAY/OBJECT value explicitly calls vw_json_object_get/
 * _array_foreach again on that value's span — recursion depth is then
 * bounded by how many times the *gateway's own code* chooses to do that
 * (a small fixed number for this project's endpoint shapes), not by
 * anything in the input.
 */

#include "../core/vw_proto.h"  /* vw_err_t */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VW_JSON_STRING = 0,
    VW_JSON_NUMBER = 1,
    VW_JSON_BOOL   = 2,
    VW_JSON_NULL   = 3,
    VW_JSON_ARRAY  = 4,
    VW_JSON_OBJECT = 5,
} vw_json_kind_t;

/*
 * A raw span into the caller's original buffer — never a copy.
 * For STRING: start/len describe the content between the quotes, still
 * JSON-escaped — use vw_json_string_decode to unescape.
 * For NUMBER: number_val holds the parsed integer value (this module's
 * scope is integers only; a value containing '.'/'e'/'E' is rejected as
 * VW_ERR_PROTO_INVALID rather than silently truncated).
 * For BOOL: bool_val holds 0/1.
 * For ARRAY/OBJECT: start/len span the whole value including its
 * brackets/braces — pass to vw_json_array_foreach/vw_json_object_get to
 * look inside.
 */
typedef struct {
    vw_json_kind_t  kind;
    const char     *start;
    size_t          len;
    int             bool_val;
    int64_t         number_val;
} vw_json_value_t;

/*
 * Find "key" at the top level of the JSON object spanning obj[0..obj_len)
 * (obj must start with '{' and end with the matching '}') and return its
 * value as a raw span in *out.
 *
 * Returns VW_ERR_NOT_FOUND if key is absent, VW_ERR_PROTO_INVALID if obj is
 * not a well-formed JSON object or a value can't be parsed.
 */
vw_err_t vw_json_object_get(const char *obj, size_t obj_len,
                             const char *key, vw_json_value_t *out);

/*
 * Iterate the top-level elements of a JSON array spanning arr[0..arr_len)
 * (arr must start with '[' and end with ']'). Calls cb(userdata, element)
 * for each element in order. Stops early (returns VW_OK) if cb returns
 * nonzero. Returns VW_ERR_PROTO_INVALID if arr is not a well-formed array
 * or an element can't be parsed.
 */
typedef int (*vw_json_array_cb_t)(void *userdata, vw_json_value_t element);

vw_err_t vw_json_array_foreach(const char *arr, size_t arr_len,
                                vw_json_array_cb_t cb, void *userdata);

/*
 * Unescape a JSON string value (the start/len of a VW_JSON_STRING
 * vw_json_value_t) into out_buf, handling \", \\, \/, \b, \f, \n, \r, \t,
 * and \uXXXX (including surrogate pairs, decoded to UTF-8). Always
 * NUL-terminates out_buf on success.
 * Returns VW_ERR_PROTO_TOO_LARGE if the unescaped result would not fit in
 * out_buf_size (including the trailing NUL), VW_ERR_PROTO_INVALID on a
 * malformed escape sequence.
 */
vw_err_t vw_json_string_decode(const char *escaped, size_t escaped_len,
                                char *out_buf, size_t out_buf_size,
                                size_t *out_len);

/* ── Encoding ─────────────────────────────────────────────────────────────── */

/* A minimal, single-pass, append-only JSON writer over a caller-provided
 * buffer. Caller must write in valid nesting order (object/array
 * start/end balanced, a value immediately after every write_key) — this
 * writer does not validate structure, only tracks comma placement and
 * buffer bounds. */
typedef struct {
    char   *buf;
    size_t  cap;
    size_t  len;
    int     error;       /* set once any write would overflow; further writes no-op */
    int     need_comma;  /* internal: whether the next item needs a leading comma */
} vw_json_writer_t;

void vw_json_writer_init(vw_json_writer_t *w, char *buf, size_t cap);

/* Returns VW_OK, or VW_ERR_PROTO_TOO_LARGE if any write since init overflowed. */
vw_err_t vw_json_writer_result(const vw_json_writer_t *w, size_t *out_len);

void vw_json_write_object_start(vw_json_writer_t *w);
void vw_json_write_object_end(vw_json_writer_t *w);
void vw_json_write_array_start(vw_json_writer_t *w);
void vw_json_write_array_end(vw_json_writer_t *w);

/* Writes "key": — caller must write exactly one value immediately after. */
void vw_json_write_key(vw_json_writer_t *w, const char *key);

/* Value writers. write_string escapes str (arbitrary bytes, including
 * control characters and non-ASCII UTF-8, are all escaped safely) — this
 * is the function responsible for making TASK-138's filename-rendering
 * concern a browser-side (not encoding-side) problem: whatever this writes
 * is always valid, safely-escaped JSON string content. */
void vw_json_write_string(vw_json_writer_t *w, const char *str, size_t str_len);
void vw_json_write_int(vw_json_writer_t *w, int64_t v);
void vw_json_write_uint(vw_json_writer_t *w, uint64_t v);
void vw_json_write_bool(vw_json_writer_t *w, int v);
void vw_json_write_null(vw_json_writer_t *w);

#ifdef __cplusplus
}
#endif

#endif /* VW_JSON_H */
