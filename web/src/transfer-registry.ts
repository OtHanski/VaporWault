/*
 * transfer-registry.ts — localStorage-backed record of in-progress
 * uploads/downloads, so a page reload doesn't silently lose track of a
 * transfer that was still running (TASK-00283).
 *
 * This module deliberately persists only lightweight UX metadata: which
 * file, which direction, how far it got, and enough to re-locate the
 * target on the server. It never persists:
 *   - the file's bytes or any chunk hash list (re-hashing the re-selected
 *     File is cheap; trusting a stale client-side hash cache instead of
 *     re-reading the actual bytes would be a correctness risk, not just
 *     an optimization - see api.ts's uploadFile query-before-upload flow)
 *   - a vault DEK or any other key material (vault-crypto.ts's randomDek
 *     is generated fresh per upload attempt and must never be persisted -
 *     see api.ts's uploadFileEncrypted doc comment for why that also
 *     means a vault upload can't be resumed across a reload; `resumable`
 *     below is what tells the UI not to offer that)
 *
 * A browser `File` object from an `<input type="file">` cannot be
 * re-accessed after a reload - resuming an upload always means the user
 * re-selects the file, which main.ts matches back to a record here by
 * name + size + lastModified before sending anything.
 */

export type TransferDirection = "upload" | "download";

export interface TransferRecord {
  id: string;
  // Which multi-account browser slot (main.ts/api.ts's activeSlot) this
  // transfer belongs to - all slots share one browser-wide localStorage,
  // so without this a transfer started under one account could be shown
  // (and resumed against) a different, currently-active account.
  slot: number;
  direction: TransferDirection;
  fileName: string;
  fileSize: number;
  // File.lastModified, used only to disambiguate a re-selected file from a
  // same-named-and-sized but different file. 0 for downloads (no local
  // File involved).
  fileLastModified: number;
  // Upload: the target path. Download: the source path, for display only.
  path: string;
  // Download: the version being fetched. 0 for uploads.
  versionId: number;
  // 0 = plaintext transfer.
  vaultId: number;
  // False for vault uploads (see module doc comment above) - the UI must
  // offer Discard only, never Resume, for these.
  resumable: boolean;
  totalChunks: number;
  doneChunks: number;
  startedAt: number;
}

const STORAGE_KEY = "vw_transfers";

function readAll(): TransferRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as TransferRecord[]) : [];
  } catch {
    // Corrupt/missing storage is not fatal to transfers themselves - this
    // registry is UX metadata only.
    return [];
  }
}

function writeAll(records: TransferRecord[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
  } catch {
    // Best-effort only (private browsing, quota, disabled storage) - never
    // block a transfer on this failing.
  }
}

export function startTransfer(
  rec: Omit<TransferRecord, "id" | "startedAt" | "doneChunks">,
): string {
  const id =
    typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const all = readAll();
  all.push({ ...rec, id, startedAt: Date.now(), doneChunks: 0 });
  writeAll(all);
  return id;
}

export function updateTransferProgress(
  id: string,
  doneChunks: number,
  totalChunks: number,
): void {
  const all = readAll();
  const rec = all.find((r) => r.id === id);
  if (!rec) return;
  rec.doneChunks = doneChunks;
  rec.totalChunks = totalChunks;
  writeAll(all);
}

// Call on both success and a terminal (non-retryable-in-place) failure -
// anything left in the registry after that is, by definition, either
// still running or was abandoned by a reload, which is exactly the set
// renderInterruptedTransfers() in main.ts is meant to surface.
export function removeTransfer(id: string): void {
  writeAll(readAll().filter((r) => r.id !== id));
}

// Scoped to one multi-account browser slot (main.ts/api.ts's activeSlot) -
// all slots share this one browser-wide localStorage store, so an
// unscoped listing would show (and let the UI resume) a transfer that
// belongs to a different, not-currently-active account.
export function listTransfersForSlot(slot: number): TransferRecord[] {
  return readAll().filter((r) => r.slot === slot);
}
