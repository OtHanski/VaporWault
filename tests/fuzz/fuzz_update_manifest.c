/*
 * fuzz_update_manifest.c — libFuzzer target for vw_update_manifest_parse()
 * (TASK-00297).
 *
 * The manifest's ECDSA signature is verified before this parser ever sees
 * the bytes in the real pipeline (vw_update_manifest_fetch_and_verify) —
 * but a hand-rolled parser scoped to a fixed schema is still worth fuzzing
 * directly as defense in depth, matching this project's existing practice
 * for other on-the-wire/on-disk parsers (fuzz_proto_recv, fuzz_oplog_replay).
 * A parser bug here would only ever be reachable by an attacker who could
 * also forge a valid signature — which they can't — but "never crashes on
 * arbitrary bytes" is still the correct bar for code that will see
 * attacker-influenced input.
 *
 * No structure needed in the input: raw fuzzer bytes are handed to
 * vw_update_manifest_parse() as-is, treated as a candidate JSON document.
 * Any non-VW_OK / VW_OK return is fine; a crash, hang, or sanitizer
 * violation is what this target exists to catch.
 */

#include "vw_update_manifest.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    vw_update_manifest_t out;
    (void)vw_update_manifest_parse((const char *)data, size, &out);
    return 0;
}
