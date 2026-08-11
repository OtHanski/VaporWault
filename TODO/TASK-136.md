---
id:          TASK-136
title:       Scaffold web/ TypeScript frontend build + nginx reverse-proxy config
status:      review
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-128]
blocks:      [TASK-137, TASK-138, TASK-139, TASK-140, TASK-141]
review_by:   [CQR.08]
tags:        [web, build]
---

Scaffold the static frontend per `TASK-127`'s "plain TypeScript, no SPA
framework" constraint, in a new top-level `web/` directory
(`ARCHITECTURE.md`'s updated Repository Structure).

Scope:

1. `web/` project structure: plain TypeScript source (`web/src/*.ts`)
   compiled with `tsc`/esbuild to static JS — build tooling is dev-time
   only, nothing ships to the browser but plain JS/HTML/CSS, so it doesn't
   count against the project's "minimal external runtime dependencies"
   constraint.
2. A minimal `index.html` shell and a small client-side router (hand-rolled
   — no framework) for the views `TASK-137`–`TASK-141` will add.
3. A `fetch()`-based API client module wrapping the gateway's `/api/*`
   endpoints (`TASK-132`–`TASK-135`), including session-cookie handling.
4. An example nginx config: serves `web/dist/` (or equivalent build output)
   as static assets, reverse-proxies `/api/*` to
   `vapourwault-web-gateway`'s loopback HTTP listener (`TASK-129`). Add this
   to `docs/DEPLOYMENT.md` alongside `TASK-142`'s packaging work (coordinate
   with BLD.05 rather than duplicating).
5. Wire the frontend build into CI/build docs so `VW_BUILD_WEB_GATEWAY`
   builds document how to also build+deploy `web/` (this task can leave the
   TS build as a separate `npm`/`package.json` step outside CMake — CMake
   doesn't need to orchestrate a Node build for a static-asset output).

## Acceptance criteria

- `web/` builds to a static asset directory servable by nginx with zero
  runtime framework dependency (verify: no `node_modules` package ships to
  the browser, only compiled output).
- Example nginx config in `docs/DEPLOYMENT.md` correctly proxies `/api/*`
  to the gateway and serves everything else as static files.
- Router + API client scaffold is in place for `TASK-137`–`TASK-141` to add
  actual views against, with no view logic implemented yet.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-11]: Implemented (`web/`): `package.json`/`tsconfig.json`
(plain `tsc` compile, no bundler/framework), `index.html` + `style.css`,
an `api.ts` fetch wrapper, and `nginx.conf.example`. Compiles clean with
`tsc --strict` (caught one real type-safety bug along the way — see
`TASK-137`'s note). `web/node_modules/`, `web/dist/` gitignored (build
output/dev deps, not committed).

Verified beyond just "it compiles": served the static output with a
plain HTTP server and confirmed every asset (`index.html`, `dist/main.js`,
`dist/api.js`, `style.css`) loads with the right content-type; separately,
ran the *compiled* `api.js` from Node against the real running gateway
(not just TypeScript type-checking) — see `TASK-137`/`TASK-138`'s note for
the actual request/response log. Did **not** open this in a real GUI
browser (none available in this environment) — the DOM-manipulation code
in `main.ts` (`TASK-137`/`TASK-138`) is therefore unverified in an actual
browser specifically; recommend that as the first manual check before
considering those two tasks fully done, not just this scaffold.

Moving to `review` — needs CQR.08 sign-off, with the "never opened in a
real browser" gap flagged explicitly.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave.
