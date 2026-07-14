#!/usr/bin/env bash
# run_regression.sh — Replay the seed corpus for all fuzz targets once.
#
# Usage: bash tests/fuzz/run_regression.sh <build-dir>
#
# Each fuzz binary is invoked with its corpus directory and -runs=1.
# libFuzzer exits non-zero if any corpus input causes a crash or sanitizer
# violation.  This script propagates the first non-zero exit code.
#
# The script is intentionally minimal: it is a regression check (catch
# previously-found crashes), not a coverage expansion run.  To run full
# fuzzing, invoke each binary directly with your desired -max_total_time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS_DIR="${SCRIPT_DIR}/corpus"

BUILD_DIR="${1:-}"
if [[ -z "${BUILD_DIR}" ]]; then
    echo "Usage: $0 <build-dir>" >&2
    exit 1
fi

# Resolve absolute path (the cmake build dir may be relative to repo root).
if [[ ! "${BUILD_DIR}" = /* ]]; then
    BUILD_DIR="$(pwd)/${BUILD_DIR}"
fi

BIN_DIR="${BUILD_DIR}/bin"

TARGETS=(
    fuzz_proto_recv
    fuzz_path_validate
    fuzz_oplog_replay
    fuzz_cluster_hello
    fuzz_admin_dispatch
)

RC=0

for target in "${TARGETS[@]}"; do
    bin="${BIN_DIR}/${target}"
    corpus="${CORPUS_DIR}/${target}"

    if [[ ! -x "${bin}" ]]; then
        echo "[SKIP] ${target}: binary not found at ${bin}" >&2
        continue
    fi

    if [[ ! -d "${corpus}" ]]; then
        echo "[SKIP] ${target}: no corpus directory at ${corpus}" >&2
        continue
    fi

    seed_count=$(find "${corpus}" -maxdepth 1 -type f | wc -l)
    if [[ "${seed_count}" -eq 0 ]]; then
        echo "[SKIP] ${target}: corpus directory is empty" >&2
        continue
    fi

    echo "[RUN ] ${target}: replaying ${seed_count} seed(s)"

    # -runs=0 replays each corpus file exactly once (no mutation).
    # -max_total_time is a safety ceiling if the target hangs.
    if ! "${bin}" "${corpus}" -runs=0 -max_total_time=30 2>&1; then
        echo "[FAIL] ${target}: crash or sanitizer violation" >&2
        RC=1
    else
        echo "[PASS] ${target}"
    fi
done

exit ${RC}
