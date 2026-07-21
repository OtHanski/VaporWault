---
id:          TASK-081
title:       Review, test, and (if needed) fix the new release.yml build-and-release workflow
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-21
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [ci, release, security-sensitive]
---

`.github/workflows/release.yml` was just added: on a `v*` tag push it builds Linux
(gcc, Release, GUI+SDL2 via `apt`) and Windows (MSVC, Release, GUI+SDL2 vendored from
the official SDL2 VC devel zip) in parallel, stages each into an archive
(`vaporwault-<tag>-linux-x86_64.tar.gz`, `vaporwault-<tag>-windows-x86_64.zip`), then a
`publish` job uses `gh release create` to attach both archives to a GitHub Release.

This is CI/build-pipeline work (BLD.05's domain per `CLAUDE.md`), and it needs review
before it's trusted to run against a real tag:

- It holds `permissions: contents: write` and creates a public, user-facing artifact
  (a GitHub Release) — tagged `security-sensitive` per the routing rules, so both
  SEC.07 and CQR.08 must sign off before `done`.
- It downloads an external SDL2 package over HTTPS at build time with no checksum
  pinning.
- It has not been exercised on GitHub's runners yet (no test tag has been pushed) —
  QA.06 should validate what can be validated locally before any real tag is pushed.

## Acceptance criteria

- CQR.08 reviews for quality/consistency with `.github/workflows/ci.yml`'s existing
  conventions (checkout/configure/build shape, step naming, etc).
- SEC.07 reviews for the CI-specific threat model: token/permission scope, script
  injection via unsanitized `${{ }}` expression interpolation into `run:` blocks,
  unpinned third-party actions, supply-chain integrity of the SDL2 download.
- QA.06 validates what it can without pushing a real tag (YAML validity, dry-running
  the staging/packaging shell and PowerShell logic against a faked `build/bin`,
  static-analysis tooling if available), and reports any gaps that can only be caught
  by an actual GitHub Actions run.
- All `blocking` findings resolved by BLD.05; `advisory` findings triaged (fixed or
  explicitly deferred with reasoning).
- `docs/RELEASE.md` written documenting the release process for future maintainers.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-21]: Task created and assigned to BLD.05 per `CLAUDE.md` (CI pipeline
configuration is BLD.05's domain). Tagged `security-sensitive` per routing rule 1
(token permissions + external download + public release artifact), so both CQR.08 and
SEC.07 are required reviewers. Kicking off CQR.08 and SEC.07 review, plus a QA.06
local-validation pass, in parallel.

SEC.07 [2026-07-21]: Reviewed `release.yml`. Two **blocking** findings:
1. `github.ref_name` interpolated directly as a `${{ }}` expression inside `run:`
   shell/pwsh blocks (staging steps, `gh release create`) — a classic GitHub
   Actions script-injection vector, since git ref names permit shell metacharacters
   and substitution happens at templating time, before quoting in the script has
   any effect. Combined with `contents: write`, this is a real privilege-escalation
   path. Fix: route `github.ref_name` through job-level `env:` and reference it as
   a shell/env variable instead.
2. `permissions: contents: write` declared workflow-wide instead of scoped to only
   the `publish` job, which is the only job that needs it.

Advisory (non-blocking): unpinned third-party actions (matches existing `ci.yml`
convention — recommend a separate follow-up covering both files); SDL2 zip fetched
with no integrity/checksum verification; no checksum manifest for published
archives.

CQR.08 [2026-07-21]: Reviewed `release.yml` against `ci.yml`'s conventions. No
blocking issues. Advisory: same permissions-scoping issue SEC.07 flagged (independent
confirmation); job-name prefix style diverges slightly from `ci.yml`; MSVC setup step
lost `ci.yml`'s explanatory comment; no smoke test runs built binaries before
packaging; `gh release create` has no re-run/idempotency handling (fails outright if
a release for the tag already exists); no `workflow_dispatch` trigger for a dry run;
`SDL2_VERSION` pin has no comment linking it to `VENDOR_SETUP.md`'s documented
minimum version; no checksums published alongside archives.

QA.06 [2026-07-21]: Validated locally (no tag pushed, no real GitHub Actions run).
YAML parses clean. `actionlint`/`go` unavailable on this machine — skipped, optional.
Dry-ran the Linux staging (mkdir/cp/tar) and Windows staging (New-Item/Copy-Item/
Compress-Archive) logic against faked `build/bin` contents — both produced archives
with the expected top-level directory name and file contents. Confirmed against the
real GitHub API + a real download that `SDL2-devel-2.32.10-VC.zip` exists and extracts
to a top-level `SDL2-2.32.10/` folder containing `lib/x64/SDL2.dll`, exactly matching
the workflow's `Move-Item`/`Copy-Item` assumptions. No blocking issues. Advisory: the
GUI+SDL2 build combination is only ever exercised in this release workflow, never in
`ci.yml` (which always sets `VW_BUILD_GUI=OFF`) — a GUI build regression would only
surface at release time.

BLD.05 [2026-07-21]: Resolved both blocking findings and applied several advisory
fixes to `release.yml`:
- **Blocking #1 (injection)**: `github.ref_name` (and, for `workflow_dispatch` dry
  runs, the manual `version` input) is now read once into a job-level `TAG` env var
  and referenced as `$TAG`/`$env:TAG` in every `run:` block — no `${{ }}` expression
  involving ref/tag/input values is interpolated directly into a shell or pwsh
  script body anymore.
- **Blocking #2 (permission scope)**: workflow-level `permissions` dropped to
  `contents: read`; `contents: write` is now declared only on the `publish` job.
- **Advisory fixes applied**: added a `workflow_dispatch` trigger with a `version`
  input for build-only dry runs (`publish` is gated `if: github.event_name ==
  'push'`, so a manual run can never touch the real Releases page); `gh release
  view` / `gh release upload --clobber` vs `gh release create` branch so re-running
  for an already-published tag uploads/overwrites instead of hard-failing; added
  `.sha256` checksum sidecar files for both archives (`sha256sum` on Linux,
  `Get-FileHash` on Windows) and referenced them in `docs/RELEASE.md`; pinned and
  checksum-verified the SDL2 download (`SDL2_ZIP_SHA256`, computed via
  `curl | sha256sum` against the real asset and checked in CI before extraction);
  added a comment linking `SDL2_VERSION` to `VENDOR_SETUP.md`'s documented minimum;
  restored the MSVC step's explanatory comment from `ci.yml`.
- **Deferred to `TASK-082`** (advisory, non-blocking, tracked separately to avoid
  scope creep): GUI never built in `ci.yml` itself, no pre-publish smoke test of
  built binaries, SHA-pinning third-party actions (affects `ci.yml` too — fixing
  both together keeps them consistent).
- Re-validated: YAML parses clean; re-ran the Linux staging + checksum dry run
  (`sha256sum -c` on the generated sidecar passes) and the publish job's
  create-vs-upload branch logic in a scratch directory. Wrote `docs/RELEASE.md`
  documenting the release process, versioning, dry-run usage, checksum
  verification, SDL2 vendoring/bump procedure, and the known follow-ups in
  `TASK-082`. Handing off to CQR.08 and SEC.07 to confirm the blocking findings are
  resolved before this can move to `done`.
  Note: an earlier local dry-run (before this one) used an unset scratchpad
  variable and accidentally ran its staging commands against the real repo
  working directory instead of a scratch dir — it briefly overwrote `README.md`
  and left stray files (`vaporwault-v0.0.1-test-linux-x86_64/`, its `.tar.gz`,
  a stray 0-byte `build/bin/vapourwault-gui`). Caught immediately via `git
  status`/`git diff`; `README.md` was restored with `git restore` (content
  confirmed identical to HEAD afterward) and all stray files were deleted. No
  commit had been made at that point, so nothing was lost. Recorded here for
  the record, not because it affects `release.yml` itself.

SEC.07 [2026-07-21] (re-review): Independently verified both blocking findings
against the current file (not just BLD.05's note). **Finding 1 (injection):
RESOLVED** — confirmed no `${{ github.ref_name }}` / `${{ github.event.inputs.* }}`
appears inside any `run:` block; `TAG` is only ever referenced as `$TAG`/`$env:TAG`.
The `${{ env.TAG }}` uses in `upload-artifact`'s `with: path:` fields are `with:`
inputs (runner-templated, not shell-parsed), not a code-injection sink. **Finding 2
(permission scope): RESOLVED** — workflow-level `permissions: contents: read`
confirmed; `contents: write` present only under `publish`. One new advisory found:
`--repo "${{ github.repository }}"` was still interpolated directly in a `run:`
block (low-risk given GitHub's restricted repo-slug character set, but inconsistent
with the `TAG` fix) — folded into the same `env:`-routing pattern (`REPO` var) in
the same pass as the other cleanup below. **Clean sign-off.**

CQR.08 [2026-07-21] (re-review): Reviewed the fixes for quality/consistency.
`workflow_dispatch` input plumbing, checksum steps, and the create-vs-upload branch
all read cleanly; `docs/RELEASE.md` spot-checked accurate against the real file
(binary list, SDL2 minimum-version cross-reference, dry-run and re-run/idempotency
descriptions all match). One new advisory noted: `TAG` ternary was duplicated
verbatim across both build jobs' `env:` blocks — invites drift. **Clean sign-off**,
no blocking issues; job-naming-style advisory from the original review remains
unchanged (deferred, cosmetic).

BLD.05 [2026-07-21]: Addressed both new advisory items from the re-review pass
(cheap, done opportunistically rather than deferred): moved `TAG` and `REPO` to a
single workflow-level `env:` block (previously duplicated per-job / re-derived in
`publish`) — all three jobs now read the same computed values, `publish`'s
`gh release` calls use `$REPO` instead of interpolating `${{ github.repository }}`
directly. Re-validated YAML and workflow structure (`python -c "import yaml..."`
confirms single top-level `env:` with `TAG`/`REPO`/`SDL2_*`, no job carries its own
`env:` override, `publish.permissions.contents == write` while the workflow default
is `read`). Repo left clean (`git status --porcelain` shows only the intended new
files). No blocking findings remain from either reviewer.

ARCH.00 [2026-07-21]: Both required reviewers (CQR.08, SEC.07) signed off clean on
the re-review, including independent verification of the fixes rather than trusting
BLD.05's note. No blocking findings outstanding. Advisory-only follow-ups tracked in
`TASK-082`. Closing — status: done.
