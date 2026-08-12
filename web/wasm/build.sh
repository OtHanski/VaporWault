#!/bin/bash
# build.sh — compiles vw_vault_kdf_wasm.c + the Argon2 reference
# implementation to WASM (TASK-141).
#
# Requires an activated Emscripten SDK (emcc on PATH — see
# https://emscripten.org/docs/getting_started/downloads.html, or this
# repo's own note: `~/emsdk/emsdk install latest && ~/emsdk/emsdk
# activate latest && source ~/emsdk/emsdk_env.sh`). Not part of the CMake
# build (same "separate npm-style step outside CMake" precedent as the
# rest of web/, TASK-136) and not run automatically in CI — output is
# committed to web/wasm/dist/ like any other prebuilt web asset would be
# (see TASK-142 for whether that's the right long-term call vs. building
# it in CI; not decided here).
#
# Vendors the SAME pinned Argon2 tag as the native build
# (third_party/CMakeLists.txt: phc-winner-argon2 @ 20190702) via a shallow
# clone into _deps/ (gitignored) rather than assuming a native CMake
# build has already populated one — this script has no dependency on the
# native build having run first.

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v emcc >/dev/null 2>&1; then
  echo "error: emcc not found on PATH. Activate an Emscripten SDK first:" >&2
  echo "  source ~/emsdk/emsdk_env.sh" >&2
  exit 1
fi

ARGON2_DIR=_deps/argon2
if [ ! -f "$ARGON2_DIR/src/argon2.c" ]; then
  echo "Fetching Argon2 reference source (tag 20190702, matching third_party/CMakeLists.txt)..."
  rm -rf "$ARGON2_DIR"
  git clone --branch 20190702 --depth 1 \
    https://github.com/P-H-C/phc-winner-argon2.git "$ARGON2_DIR"
fi

mkdir -p dist

emcc -O2 \
  -DARGON2_NO_THREADS \
  -I"$ARGON2_DIR/include" \
  -I"$ARGON2_DIR/src" \
  "$ARGON2_DIR/src/argon2.c" \
  "$ARGON2_DIR/src/core.c" \
  "$ARGON2_DIR/src/encoding.c" \
  "$ARGON2_DIR/src/ref.c" \
  "$ARGON2_DIR/src/blake2/blake2b.c" \
  vw_vault_kdf_wasm.c \
  -sEXPORTED_FUNCTIONS='["_vw_wasm_derive_kek","_malloc","_free"]' \
  -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8"]' \
  -sMODULARIZE=1 \
  -sEXPORT_ES6=1 \
  -sEXPORT_NAME=createVaultKdfModule \
  -sALLOW_MEMORY_GROWTH=1 \
  -sENVIRONMENT=web \
  -o dist/vw_vault_kdf.js

echo "Built dist/vw_vault_kdf.js + dist/vw_vault_kdf.wasm"
