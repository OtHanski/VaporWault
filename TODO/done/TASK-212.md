---
id:          TASK-212
title:       "Docs: email alert configuration"
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-207, TASK-208, TASK-209, TASK-210, TASK-211]
blocks:      [TASK-213]
review_by:   [CQR.08]
tags:        [docs]
---

## Work

- `docs/DEPLOYMENT.md`: new section documenting the `notify.*`
  `vapourwaultd.conf` keys from `TASK-208` (what each admin category
  means, what threshold/window each is measured against, the
  fail-loud-on-misconfiguration behavior), placed near the existing SMTP
  relay configuration section since it depends on it.
- `docs/CLIENT_GETTING_STARTED.md`: a short, plain-language note on the
  user-facing notification toggles (`TASK-209`/`210`/`211`) — what each
  one means and how to turn it on, written for the same non-technical
  audience the rest of that document targets.

## Acceptance criteria

- A new admin reading `docs/DEPLOYMENT.md` alone can correctly configure
  admin alerts without reading source code.
- A non-technical end user reading `docs/CLIENT_GETTING_STARTED.md` can
  find and enable notification preferences without help.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

BLD.05 [2026-08-27]: Implemented.

- `docs/DEPLOYMENT.md`: new "Admin operational email alerts" section,
  placed immediately after the existing SMTP section (it depends on it)
  and before Cluster. Documents all five `notify.*` category keys plus
  the four threshold-override keys, each with its default and what
  condition it measures, the fail-loud-on-misconfiguration behavior
  (stated as a deliberate design choice with the reasoning, not just "it
  errors"), and a worked example config snippet. Cross-references
  `docs/CLIENT_GETTING_STARTED.md` for the four separate per-user
  categories so an admin reading this section doesn't confuse the two
  surfaces.
- `docs/CLIENT_GETTING_STARTED.md`: new "Email notifications" section
  under Part 2 (Everyday use), placed after "Pausing sync" — plain
  language, a table naming the same four categories `TASK-210`'s GUI
  panel and the web frontend's Settings page use, explicitly noting the
  default-off posture and that this looks the same on desktop and web.
  Deliberately does not mention `vapourwault-cli notify` — this document
  is written for the same non-technical audience its own existing
  sections target (no CLI usage anywhere else in this doc either).

## Acceptance criteria

- **A new admin reading `docs/DEPLOYMENT.md` alone can correctly
  configure admin alerts without reading source code**: every key, its
  default, its threshold's unit/meaning, and the required-recipient rule
  are all stated in the doc itself; verified by re-reading the new
  section as if seeing it for the first time and confirming nothing
  requires cross-referencing `vw_notify.c`/`vw_server_main.c` to
  understand.
- **A non-technical end user reading `docs/CLIENT_GETTING_STARTED.md` can
  find and enable notification preferences without help**: the new
  section names the exact menu path (Settings → Email notifications,
  matching `TASK-210`'s real GUI label) and describes each category in
  plain outcome-language ("someone shares something with me") rather than
  the internal category name.

Moving to `review`.

CQR.08 [2026-08-27]: Reviewed for accuracy and consistency.

- Cross-checked every documented key name and default in the new
  `docs/DEPLOYMENT.md` section against `vw_server_main.c`'s actual config
  parsing/defaults (`cfg_defaults`, the `notify.*` parsing block) and
  `vw_notify.h`'s `VW_NOTIFY_*_DEFAULT` macros — all match exactly,
  including the threshold defaults (1000/90/10/300). The fail-loud
  behavior description matches `cfg_validate`'s real check.
- The `CLIENT_GETTING_STARTED.md` category descriptions match `TASK-210`'s
  actual GUI checkbox labels and `TASK-211`'s web frontend labels, not
  just the internal category names — a non-technical reader matching
  words on screen to words in the doc will find the right checkbox.
- Section placement in both documents follows the task's own instruction
  (near SMTP; after an existing "everyday use" section) rather than being
  tacked on at the end of either file.
- No blocking findings. Approved.

Moving to `done`.
