---
id:          TASK-119
title:       Resolve mbedTLS version mismatch between vendored submodule and FetchContent pin
status:      todo
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-04
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [build, dependencies, security-sensitive]
---

Surfaced by a 2026-08-04 project-state review. The repo has **two
independent, disagreeing mechanisms** pointing at mbedTLS:

- `.gitmodules` / `third_party/mbedtls` — a git submodule, currently
  checked out at v3.6.2.
- `third_party/CMakeLists.txt` (lines 20-25) — a `FetchContent_Declare`
  that always fetches a fresh clone of mbedTLS from GitHub at
  `GIT_TAG v3.6.3` via `FetchContent_MakeAvailable`, entirely independent of
  the submodule checkout.

Reading `third_party/CMakeLists.txt` closely: the actual build **always**
uses the `FetchContent` copy (v3.6.3) — nothing in that file references
`third_party/mbedtls` (the submodule path) at all. That means the checked-
out submodule is currently dead weight: it's present in the repo, gives the
false impression that it's what gets compiled in, and doesn't even match
the version that actually does. This is a build-hygiene and supply-chain-
clarity problem regardless of whether v3.6.2 or v3.6.3 individually has any
known issue — a contributor auditing "what crypto library version are we
actually shipping" would currently get the wrong answer by checking the
submodule.

Tagged `security-sensitive` since this is the project's one approved TLS/
crypto dependency (per project memory: "mbedTLS only — no libsodium, no
OpenSSL") and confirming exactly which version is compiled in, with a
single source of truth, is a prerequisite for taking any future mbedTLS CVE
seriously.

## Acceptance criteria

- Pick one mechanism and remove the other — either:
  (a) drop the `FetchContent` fetch and build from the vendored
      `third_party/mbedtls` submodule directly (better for reproducible/
      offline builds — no network fetch at configure time — and it's the
      same pattern already used for Argon2/Dear ImGui/SDL2 per
      `VENDOR_SETUP.md`), bumping the submodule to whichever version is
      chosen, or
  (b) remove the `third_party/mbedtls` submodule entirely and keep
      `FetchContent` as the sole source, if there's a reason (e.g. CI cache
      behavior) FetchContent was chosen deliberately over the submodule
      pattern the other three deps use.
- Whichever is chosen, confirm and document (a one-line comment in
  `third_party/CMakeLists.txt` is enough) which mbedTLS version actually
  ends up compiled in, and check it against mbedTLS's published CVE/
  security-advisory list at the time this task closes.
- `VENDOR_SETUP.md` updated if the chosen mechanism changes what a fresh
  clone needs to do (e.g. `git submodule update --init` vs. "just run
  cmake, it fetches automatically").

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested.
Priority high — cheap to fix, and "which crypto library version are we
actually building" should never be an ambiguous question for the project's
one approved TLS dependency.
