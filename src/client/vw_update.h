#ifndef VW_UPDATE_H
#define VW_UPDATE_H

/*
 * vw_update — client auto-update orchestration (TASK-00298,
 * ARCHITECTURE.md Phase 23): version-trigger comparison, verified asset
 * download, staged extraction, and handoff to the vapourwault-updater
 * helper that performs the actual file swap and relaunch.
 *
 * Trust boundary this module exists to preserve: the server's advertised
 * version (docs/PROTOCOL.md §6.4) is only ever a trigger HINT. Nothing
 * here ever installs anything on the strength of that hint alone — every
 * real decision is re-derived from the independently fetched, ECDSA-
 * verified update-manifest (vw_update_manifest.h) and the SHA-256 of the
 * downloaded asset. A compromised or merely stale server can at most
 * cause a spurious check against GitHub; it can never cause an unverified
 * install.
 */

#include "../core/vw_proto.h"   /* vw_err_t */
#include "vw_update_manifest.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Compares server_advertised_version (untrusted hint, from
 * vw_proto_update_hint_t) against the compiled VW_VERSION_STRING using a
 * narrow major.minor.patch integer comparison — no semver pre-release/
 * build-metadata handling in v1 (a known, accepted limitation: this
 * project's own releases only ever use plain MAJOR.MINOR.PATCH tags, see
 * docs/RELEASE.md). If the hint looks newer, fetches and verifies the
 * real update-manifest (vw_update_manifest_fetch_and_verify) — the
 * actual source of truth — and re-checks ITS signed release_version
 * against the same comparison before reporting an update as available;
 * the hint is only ever a reason to check, never the final word.
 *
 * server_advertised_version may be NULL (nothing to compare against —
 * *out_available is set to 0 without any network activity).
 *
 * *out_available is set to 1 only when a validly-signed, newer-than-local
 * manifest was actually fetched (in which case *out_manifest is
 * populated); 0 otherwise, INCLUDING on a network/verification failure —
 * callers must still check the return code to distinguish "checked,
 * nothing newer" (VW_OK, *out_available==0) from "the check itself
 * failed" (non-VW_OK), but either way a failed check is never fatal to
 * the caller's own connect/resume flow — this is a best-effort background
 * check riding an already-happening connection, not a blocking operation.
 */
vw_err_t vw_update_check_trigger(const char *state_dir,
                                  const char *server_advertised_version,
                                  vw_update_manifest_t *out_manifest,
                                  int *out_available);

/*
 * Returns 1 if candidate_version is strictly newer than VW_VERSION_STRING
 * under the same narrow major.minor.patch comparison
 * vw_update_check_trigger() uses internally, 0 otherwise (including on
 * unparseable input). Exposed so callers that already hold an
 * independently-fetched, verified manifest (e.g. vw_daemon.c's daily
 * auto-policy check) don't have to re-fetch just to reuse the comparison
 * vw_update_check_trigger() would otherwise perform a second time.
 */
int vw_update_version_is_newer_than_current(const char *candidate_version);

/*
 * Pure scheduling decision for the daemon's headless/auto-policy daily
 * background check (see vw_daemon.c's maybe_run_daily_auto_check) —
 * pulled out as its own testable function rather than left inline, since
 * TASK-00298's own acceptance criteria call for verifying this fires on a
 * schedule in a test harness, not just by code inspection.
 *
 * Returns 1 (due) when last_check_unix == 0 (never checked yet — the
 * fresh-install case this whole background timer exists for) or when at
 * least interval_secs has elapsed since last_check_unix; 0 otherwise.
 * now_unix < last_check_unix (a clock that moved backward) is treated as
 * NOT due, not as an overflow/underflow — never used to force a spurious
 * extra check.
 */
int vw_update_daily_check_due(int64_t last_check_unix, int64_t now_unix,
                               uint32_t interval_secs);

/*
 * Downloads this platform's portable asset from the (already verified)
 * manifest's own signed, version-pinned URL
 * (releases/download/v<release_version>/<filename> — never `latest` a
 * second time, to avoid a TOCTOU race against a newer release landing
 * between the manifest fetch and this call), verifies its SHA-256 against
 * the manifest's signed value, and writes it to
 * <staging_dir>/<filename-from-manifest> ONLY after verification succeeds
 * — a mismatch means nothing is ever written to disk.
 *
 * Returns VW_ERR_UPDATE_ASSET_MISMATCH if no asset entry matches this
 * platform/arch/portable dist_kind, or if the downloaded bytes' SHA-256
 * doesn't match. On VW_OK, *out_archive_path (a caller-provided buffer of
 * out_cap bytes) holds the full path to the verified, written file.
 */
vw_err_t vw_update_download_and_verify_asset(const vw_update_manifest_t *m,
                                              const char *staging_dir,
                                              char *out_archive_path,
                                              size_t out_cap);

/*
 * Extracts archive_path (a portable .tar.gz on Linux / .zip on Windows,
 * as produced by vw_update_download_and_verify_asset above) into a fresh
 * subdirectory of its own containing directory, then spawns the sibling
 * vapourwault-updater helper (detached, passed this process's own PID via
 * --wait-pid) to perform the actual file swap into install_dir and
 * relaunch — this function does NOT itself touch install_dir, wait for
 * the helper, or terminate this process; see vw_daemon.c's integration
 * for the caller's remaining responsibility (its own existing graceful-
 * shutdown path, then exit) once this returns VW_OK.
 *
 * The release archive itself wraps its payload in one top-level directory
 * named exactly like the archive's own filename minus its extension (see
 * release.yml's staging step) — this function resolves that nested
 * directory after extraction and passes IT, not the bare extraction
 * directory, as the updater's --staging argument. Returns VW_ERR_IO if
 * that expected nested directory isn't present post-extraction, rather
 * than handing the updater a staging directory it would silently apply
 * wrong (or apply nothing from, on Windows — see vw_update.c).
 *
 * install_dir must be the real, currently-running install directory
 * (vw_client_self_exe_dir()) — the helper is never invoked with a target
 * directory this process didn't explicitly resolve itself.
 */
vw_err_t vw_update_stage_and_apply(const char *archive_path,
                                    const char *install_dir);

#ifdef __cplusplus
}
#endif

#endif /* VW_UPDATE_H */
