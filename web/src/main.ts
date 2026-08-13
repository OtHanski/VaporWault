/*
 * main.ts — login view (TASK-137) + file browser view (TASK-138).
 * Single static page, two sections toggled via `hidden`, no router
 * library and no SPA framework (TASK-136's constraint).
 */

import {
  login,
  loginWithOtp,
  logout,
  listFiles,
  mkdir,
  deleteFile,
  moveFile,
  uploadFile,
  downloadFile,
  listVersions,
  restoreVersion,
  grantShare,
  revokeShare,
  listShares,
  createLink,
  revokeLink,
  listLinks,
  filesStat,
  vaultCreate,
  vaultKeyFetch,
  vaultList,
  uploadFileEncrypted,
  downloadFileEncrypted,
  type FileEntry,
  type VersionEntry,
  type ShareEntry,
  type LinkEntry,
} from "./api.js";

// ── Element lookups ─────────────────────────────────────────────────────────

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing element #${id}`);
  return e as T;
}

const loginView = el<HTMLElement>("login-view");
const browserView = el<HTMLElement>("browser-view");
const loginForm = el<HTMLFormElement>("login-form");
const usernameInput = el<HTMLInputElement>("login-username");
const passwordInput = el<HTMLInputElement>("login-password");
const otpField = el<HTMLElement>("otp-field");
const otpInput = el<HTMLInputElement>("login-otp");
const loginError = el<HTMLElement>("login-error");
const logoutBtn = el<HTMLButtonElement>("logout-btn");
const mkdirBtn = el<HTMLButtonElement>("mkdir-btn");
const currentPathLabel = el<HTMLElement>("current-path");
const fileTableBody = el<HTMLTableSectionElement>("file-table-body");
const browserError = el<HTMLElement>("browser-error");
const uploadBtn = el<HTMLButtonElement>("upload-btn");
const uploadInput = el<HTMLInputElement>("upload-input");
const transferList = el<HTMLUListElement>("transfer-list");
const vaultCreateBtn = el<HTMLButtonElement>("vault-create-btn");
const vaultBanner = el<HTMLElement>("vault-banner");
const vaultBannerText = el<HTMLElement>("vault-banner-text");
const vaultUnlockBtn = el<HTMLButtonElement>("vault-unlock-btn");
const vaultLockBtn = el<HTMLButtonElement>("vault-lock-btn");

const historyView = el<HTMLElement>("history-view");
const historyFileLabel = el<HTMLElement>("history-file-label");
const historyBackBtn = el<HTMLButtonElement>("history-back-btn");
const versionTableBody = el<HTMLTableSectionElement>("version-table-body");
const historyError = el<HTMLElement>("history-error");

const shareView = el<HTMLElement>("share-view");
const shareFileLabel = el<HTMLElement>("share-file-label");
const shareBackBtn = el<HTMLButtonElement>("share-back-btn");
const shareUsernameInput = el<HTMLInputElement>("share-username");
const sharePermissionSelect = el<HTMLSelectElement>("share-permission");
const shareGrantBtn = el<HTMLButtonElement>("share-grant-btn");
const shareTableBody = el<HTMLTableSectionElement>("share-table-body");
const linkCreateBtn = el<HTMLButtonElement>("link-create-btn");
const linkNewTokenBox = el<HTMLElement>("link-new-token");
const linkNewTokenInput = el<HTMLInputElement>("link-new-token-input");
const linkCopyBtn = el<HTMLButtonElement>("link-copy-btn");
const linkDismissBtn = el<HTMLButtonElement>("link-dismiss-btn");
const linkTableBody = el<HTMLTableSectionElement>("link-table-body");
const shareError = el<HTMLElement>("share-error");

// ── State ────────────────────────────────────────────────────────────────
//
// Username/password are kept in memory ONLY for the duration of the 2FA
// round trip (initial submit -> "otp_required" -> resubmit with the code)
// - never persisted (localStorage/sessionStorage), matching TASK-137's
// scope note. Cleared immediately on either success or final failure.

let pendingUsername: string | null = null;
let pendingPassword: string | null = null;
let currentPath = "/";
let currentFolderId = 0;

// The unlocked VK lives only in this in-memory variable for as long as
// the tab is open (TASK-141's own passphrase/key handling scope: no
// persistence anywhere, cleared on lock/logout/tab close). Nothing here
// is ever sent to the gateway.
let unlockedVault: { vaultId: number; folderFileId: number; vk: Uint8Array } | null = null;

function showError(target: HTMLElement, message: string): void {
  target.textContent = message;
  target.hidden = false;
}

function clearError(target: HTMLElement): void {
  target.hidden = true;
  target.textContent = "";
}

function forgetPendingCredentials(): void {
  pendingUsername = null;
  pendingPassword = null;
  otpField.hidden = true;
  otpInput.value = "";
}

// ── Login view (TASK-137) ───────────────────────────────────────────────

loginForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  clearError(loginError);
  void handleLoginSubmit();
});

async function handleLoginSubmit(): Promise<void> {
  const otpVisible = !otpField.hidden;
  const username = otpVisible && pendingUsername !== null ? pendingUsername : usernameInput.value;
  const password = otpVisible && pendingPassword !== null ? pendingPassword : passwordInput.value;

  const result = otpVisible
    ? await loginWithOtp(username, password, otpInput.value)
    : await login(username, password);

  if (result.ok) {
    forgetPendingCredentials();
    passwordInput.value = "";
    await enterBrowserView();
    return;
  }

  if (result.data.status === "otp_required") {
    pendingUsername = username;
    pendingPassword = password;
    otpField.hidden = false;
    otpInput.focus();
    return;
  }

  if (result.data.status === "otp_invalid") {
    showError(loginError, "Incorrect verification code.");
    otpInput.value = "";
    otpInput.focus();
    return;
  }

  // bad_credentials, server_unreachable, or anything else: deliberately
  // not distinguished in the UI beyond this generic message - matching
  // the server's own anti-enumeration design intent (don't reveal which
  // factor failed or whether the account exists).
  forgetPendingCredentials();
  passwordInput.value = "";
  showError(loginError, "Login failed. Check your username and password.");
}

logoutBtn.addEventListener("click", () => {
  void handleLogout();
});

async function handleLogout(): Promise<void> {
  await logout();
  browserView.hidden = true;
  loginView.hidden = false;
  usernameInput.value = "";
  passwordInput.value = "";
  loginForm.reset();
}

// ── File browser view (TASK-138) ────────────────────────────────────────

async function enterBrowserView(): Promise<void> {
  loginView.hidden = true;
  browserView.hidden = false;
  currentPath = "/";
  await refreshFileList();
}

function formatSize(bytes: number): string {
  if (bytes === 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }
  return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatMtime(unixSeconds: number): string {
  if (unixSeconds === 0) return "-";
  return new Date(unixSeconds * 1000).toLocaleString();
}

function joinPath(base: string, name: string): string {
  return base.endsWith("/") ? `${base}${name}` : `${base}/${name}`;
}

async function refreshFileList(): Promise<void> {
  clearError(browserError);
  currentPathLabel.textContent = currentPath;

  const result = await listFiles(currentPath, false);
  if (!result.ok) {
    showError(browserError, `Could not list "${currentPath}": ${result.data.status ?? "error"}`);
    return;
  }

  renderFileTable(result.data);
  await resolveCurrentFolderId();
  await refreshVaultBanner();
}

// currentPath is resolved to a file_id via stat, rather than tracked
// through navigation clicks alone, so breadcrumb "go up" navigation stays
// correct too (a click into a folder row has the id right on the
// FileEntry, but going up a breadcrumb level doesn't) - one extra
// request per navigation, worth it for correctness over both paths.
async function resolveCurrentFolderId(): Promise<void> {
  if (currentPath === "/") {
    currentFolderId = 0;
    return;
  }
  const result = await filesStat(currentPath);
  currentFolderId = result.ok ? result.data.file_id : 0;
}

/*
 * currentFolderVaultId (0 = not a vault folder) decides plaintext vs.
 * encrypted for a brand-new upload, which has no vault_id of its own yet
 * to consult — this remains the only signal available at upload time.
 *
 * It is deliberately NOT used for any *existing* entry's plaintext-vs-
 * encrypted decision (download, lock-icon rendering) — TASK-156 closed
 * the wire-protocol gap that used to force that folder-level inference
 * (FILE_LIST_RESP now carries a real per-entry vault_id, and
 * vw_client_file_list populates FileEntry.vault_id from it). An entry's
 * own vault_id is the correct signal there and handles cases the
 * folder-level inference got wrong: a file keeps its vault_id when moved
 * out of the vault's registered folder (FILE_MOVE never touches version
 * metadata), so a plain "is the containing folder a registered vault"
 * check would wrongly treat it as plaintext post-move.
 */
let currentFolderVaultId = 0;

async function refreshVaultBanner(): Promise<void> {
  const result = await vaultList();
  if (!result.ok) {
    vaultBanner.hidden = true;
    currentFolderVaultId = 0;
    return;
  }
  const vault = result.data.find((v) => v.folder_file_id === currentFolderId);
  if (!vault) {
    vaultBanner.hidden = true;
    currentFolderVaultId = 0;
    if (unlockedVault && unlockedVault.folderFileId !== currentFolderId) {
      // Navigated away from the unlocked vault's folder - lock it rather
      // than leave the VK sitting in memory scoped to a view the user
      // isn't even looking at anymore.
      lockVault();
    }
    return;
  }

  currentFolderVaultId = vault.vault_id;
  vaultBanner.hidden = false;
  const isUnlocked = unlockedVault?.vaultId === vault.vault_id;
  vaultBannerText.textContent = isUnlocked
    ? `This folder is an encrypted vault (unlocked).`
    : `This folder is an encrypted vault. Unlock it to upload/download files.`;
  vaultUnlockBtn.hidden = isUnlocked;
  vaultLockBtn.hidden = !isUnlocked;
}

function lockVault(): void {
  if (unlockedVault) {
    // Best-effort zero of the in-memory VK - a Uint8Array can be
    // overwritten, unlike the passphrase string that produced it earlier
    // in the chain (a JS string is immutable and can't be zeroed; this
    // is as much as this layer can do).
    unlockedVault.vk.fill(0);
  }
  unlockedVault = null;
}

vaultLockBtn.addEventListener("click", () => {
  lockVault();
  void refreshVaultBanner();
});

vaultUnlockBtn.addEventListener("click", () => {
  void handleUnlockVault();
});

async function handleUnlockVault(): Promise<void> {
  const passphrase = window.prompt(
    "Enter this vault's passphrase.\n\n" +
      "Reminder: if you lose this passphrase, the encrypted contents cannot " +
      "be recovered by anyone, including the server operator.",
  );
  if (!passphrase) return;

  const keyFetchResult = await vaultKeyFetch(currentFolderVaultId);
  if (!keyFetchResult.ok) {
    showError(browserError, `Could not unlock vault: ${keyFetchResult.data.status ?? "error"}`);
    return;
  }

  try {
    const { deriveKek, unwrapKey, hexToBytes } = await import("./vault-crypto.js");
    const salt = hexToBytes(keyFetchResult.data.kdf_salt);
    const paramsBytes = hexToBytes(keyFetchResult.data.kdf_params);
    const paramsView = new DataView(
      paramsBytes.buffer,
      paramsBytes.byteOffset,
      paramsBytes.byteLength,
    );
    const kdfParams = {
      memCostKib: paramsView.getUint32(0, true),
      timeCost: paramsView.getUint32(4, true),
      parallelism: paramsView.getUint32(8, true),
    };

    const kek = await deriveKek(passphrase, salt, kdfParams);
    const wrappedVk = hexToBytes(keyFetchResult.data.wrapped_vk);
    const vk = await unwrapKey(kek, wrappedVk);
    kek.fill(0);

    unlockedVault = { vaultId: currentFolderVaultId, folderFileId: currentFolderId, vk };
    await refreshVaultBanner();
  } catch (err) {
    showError(
      browserError,
      err instanceof Error ? err.message : "Could not unlock vault (wrong passphrase?)",
    );
  }
}

vaultCreateBtn.addEventListener("click", () => {
  void handleCreateVault();
});

async function handleCreateVault(): Promise<void> {
  if (currentFolderId === 0) {
    showError(browserError, "The root folder cannot be made a vault - create a subfolder first.");
    return;
  }

  const disclosureAccepted = window.confirm(
    "Make this folder an encrypted vault?\n\n" +
      "1. Passphrase loss is unrecoverable: if you forget this passphrase, " +
      "nobody - including the server operator - can recover the contents.\n\n" +
      "2. Metadata stays visible: filenames, folder structure, and file " +
      "sizes are still visible to the server. Only file CONTENTS are " +
      "encrypted.\n\n" +
      "3. Every edit re-uploads the whole file: encrypted files don't " +
      "support delta-sync, so editing a large encrypted file re-uploads it " +
      "in full each time.\n\n" +
      "Continue?",
  );
  if (!disclosureAccepted) return;

  const passphrase = window.prompt("Choose a passphrase for this vault (at least 8 characters):");
  if (!passphrase || passphrase.length < 8) {
    if (passphrase !== null) showError(browserError, "Passphrase must be at least 8 characters.");
    return;
  }
  const confirmPassphrase = window.prompt("Re-enter the passphrase to confirm:");
  if (confirmPassphrase !== passphrase) {
    showError(browserError, "Passphrases did not match - vault not created.");
    return;
  }

  const { randomSalt, deriveKek, randomDek, wrapKey, bytesToHex } = await import(
    "./vault-crypto.js"
  );

  // Matches vw_vault.c's own vw_vault_setup floor exactly
  // (VW_VAULT_ARGON2_MIN_MEM_KB/_MIN_TIME_COST/_PARALLELISM) - a weaker
  // param set is rejected both by the WASM KDF wrapper and, redundantly,
  // by the native server-side vw_crypto_vault_derive_kek if this vault is
  // ever unlocked from the native client instead.
  const kdfParams = { memCostKib: 19456, timeCost: 2, parallelism: 1 };
  const salt = randomSalt();
  const kek = await deriveKek(passphrase, salt, kdfParams);
  const vk = randomDek(); // same random-32-bytes shape as a DEK; naming reflects its role here
  const wrappedVk = await wrapKey(kek, vk);
  kek.fill(0);
  vk.fill(0);

  const paramsBytes = new Uint8Array(12);
  new DataView(paramsBytes.buffer).setUint32(0, kdfParams.memCostKib, true);
  new DataView(paramsBytes.buffer).setUint32(4, kdfParams.timeCost, true);
  new DataView(paramsBytes.buffer).setUint32(8, kdfParams.parallelism, true);

  const result = await vaultCreate(
    currentFolderId,
    bytesToHex(wrappedVk),
    bytesToHex(salt),
    bytesToHex(paramsBytes),
  );
  if (!result.ok) {
    showError(browserError, `Could not create vault: ${result.data.status ?? "error"}`);
    return;
  }

  await refreshVaultBanner();
}

function renderFileTable(entries: FileEntry[]): void {
  fileTableBody.replaceChildren();

  const sorted = [...entries].sort((a, b) => {
    if (a.entry_type !== b.entry_type) return b.entry_type - a.entry_type; // folders first
    return a.name.localeCompare(b.name);
  });

  for (const entry of sorted) {
    fileTableBody.appendChild(renderFileRow(entry));
  }
}

function renderFileRow(entry: FileEntry): HTMLTableRowElement {
  const row = document.createElement("tr");
  const isDir = entry.entry_type === 1;

  const nameCell = document.createElement("td");
  const nameLink = document.createElement("a");
  nameLink.href = "#";
  // textContent, never innerHTML - a shared folder can contain files
  // named by someone else; this is what keeps arbitrary filenames from
  // ever being interpreted as markup (TASK-138's flagged XSS concern).
  const lockPrefix = !isDir && entry.vault_id !== 0 ? "\u{1F512} " : "";
  nameLink.textContent = lockPrefix + (isDir ? "\u{1F4C1} " : "\u{1F4C4} ") + entry.name;
  if (isDir) {
    nameLink.addEventListener("click", (ev) => {
      ev.preventDefault();
      currentPath = joinPath(currentPath, entry.name);
      void refreshFileList();
    });
  }
  nameCell.appendChild(nameLink);
  row.appendChild(nameCell);

  const sizeCell = document.createElement("td");
  sizeCell.textContent = isDir ? "-" : formatSize(entry.size_bytes);
  row.appendChild(sizeCell);

  const mtimeCell = document.createElement("td");
  mtimeCell.textContent = formatMtime(entry.mtime_unix);
  row.appendChild(mtimeCell);

  const actionsCell = document.createElement("td");
  if (!isDir) {
    const downloadBtn = document.createElement("button");
    downloadBtn.textContent = "Download";
    downloadBtn.className = "row-action";
    downloadBtn.addEventListener("click", () => {
      void handleDownload(entry);
    });
    actionsCell.appendChild(downloadBtn);

    const historyBtn = document.createElement("button");
    historyBtn.textContent = "History";
    historyBtn.className = "row-action";
    historyBtn.addEventListener("click", () => {
      void enterHistoryView(entry);
    });
    actionsCell.appendChild(historyBtn);
  }
  const shareBtn = document.createElement("button");
  shareBtn.textContent = "Share";
  shareBtn.className = "row-action";
  shareBtn.addEventListener("click", () => {
    void enterShareView(entry);
  });
  actionsCell.appendChild(shareBtn);
  const renameBtn = document.createElement("button");
  renameBtn.textContent = "Rename";
  renameBtn.className = "row-action";
  renameBtn.addEventListener("click", () => {
    void handleRename(entry);
  });
  actionsCell.appendChild(renameBtn);
  const deleteBtn = document.createElement("button");
  deleteBtn.textContent = "Delete";
  deleteBtn.className = "row-action";
  deleteBtn.addEventListener("click", () => {
    void handleDelete(entry);
  });
  actionsCell.appendChild(deleteBtn);
  row.appendChild(actionsCell);

  return row;
}

async function handleDelete(entry: FileEntry): Promise<void> {
  const path = joinPath(currentPath, entry.name);
  if (!window.confirm(`Delete "${entry.name}"?`)) return;

  const result = await deleteFile(path);
  if (!result.ok) {
    showError(browserError, `Could not delete "${entry.name}": ${result.data.status ?? "error"}`);
    return;
  }
  await refreshFileList();
}

mkdirBtn.addEventListener("click", () => {
  void handleMkdir();
});

async function handleMkdir(): Promise<void> {
  const name = window.prompt("New folder name:");
  if (!name) return;

  // currentFolderId, not the default 0 - otherwise every new folder lands
  // at the filesystem root regardless of which folder is being browsed
  // (a real bug found during TASK-138's CQR.08 review: the folder was
  // created at "/", refreshFileList() then re-listed the folder actually
  // being browsed, and it silently never appeared there).
  const result = await mkdir(name, currentFolderId);
  if (!result.ok) {
    showError(browserError, `Could not create "${name}": ${result.data.status ?? "error"}`);
    return;
  }
  await refreshFileList();
}

async function handleRename(entry: FileEntry): Promise<void> {
  const newName = window.prompt("Rename to:", entry.name);
  if (!newName || newName === entry.name) return;

  // Same currentFolderId requirement as handleMkdir above - moveFile's
  // own newParentDirId default is also 0, so an in-place rename that
  // omitted this would silently relocate the entry to the filesystem
  // root instead of renaming it where it sits.
  const result = await moveFile(entry.file_id, newName, currentFolderId);
  if (!result.ok) {
    showError(browserError, `Could not rename "${entry.name}": ${result.data.status ?? "error"}`);
    return;
  }
  await refreshFileList();
}

// ── Upload / download with progress (TASK-139) ──────────────────────────
//
// The browser drives the chunk loop itself (api.ts's uploadFile/
// downloadFile), one HTTP request per chunk - this is what gives real
// per-file byte progress without any gateway-side status/polling API
// (TASK-127's design note). A transfer item's label and bar are updated
// via textContent/style.width only, never innerHTML - same XSS-safety
// rule as the file table (TASK-138), since a transfer label embeds a
// user-controlled filename.

interface TransferHandle {
  setProgress(bytesDone: number, bytesTotal: number): void;
  /* onRetry, if given, adds a Retry button that re-runs the transfer from
   * scratch (chunk-level dedup, TASK-133's chunk_upload_if_missing, means
   * a retry doesn't re-transfer bytes the server already has - only a
   * fresh commit is needed for chunks that did land). */
  setFailed(message: string, onRetry?: () => void): void;
  remove(): void;
}

function createTransferItem(label: string): TransferHandle {
  const item = document.createElement("li");
  item.className = "transfer-item";

  const labelRow = document.createElement("div");
  labelRow.className = "transfer-label";
  const nameSpan = document.createElement("span");
  nameSpan.textContent = label;
  const statSpan = document.createElement("span");
  statSpan.textContent = "0%";
  labelRow.appendChild(nameSpan);
  labelRow.appendChild(statSpan);

  const track = document.createElement("div");
  track.className = "transfer-bar-track";
  const fill = document.createElement("div");
  fill.className = "transfer-bar-fill";
  track.appendChild(fill);

  item.appendChild(labelRow);
  item.appendChild(track);
  transferList.appendChild(item);

  return {
    setProgress(bytesDone: number, bytesTotal: number) {
      const pct = bytesTotal > 0 ? Math.round((bytesDone / bytesTotal) * 100) : 100;
      fill.style.width = `${pct}%`;
      statSpan.textContent = `${pct}%`;
    },
    setFailed(message: string, onRetry?: () => void) {
      item.classList.add("failed");
      statSpan.textContent = message;
      if (onRetry) {
        const retryBtn = document.createElement("button");
        retryBtn.textContent = "Retry";
        retryBtn.className = "row-action";
        retryBtn.addEventListener("click", () => {
          item.classList.remove("failed");
          retryBtn.remove();
          onRetry();
        });
        labelRow.appendChild(retryBtn);
      }
    },
    remove() {
      item.remove();
    },
  };
}

uploadBtn.addEventListener("click", () => {
  uploadInput.click();
});

uploadInput.addEventListener("change", () => {
  const files = uploadInput.files;
  uploadInput.value = ""; // allow re-selecting the same file later
  if (!files || files.length === 0) return;
  void handleUpload(Array.from(files));
});

async function handleUpload(files: File[]): Promise<void> {
  for (const file of files) {
    await uploadOne(file);
  }
  await refreshFileList();
}

async function uploadOne(file: File): Promise<void> {
  const path = joinPath(currentPath, file.name);
  const handle = createTransferItem(`Uploading ${file.name}`);

  // currentFolderVaultId != 0 means THIS folder is a registered vault -
  // uploads here must always be encrypted, never fall back to plaintext
  // just because the vault happens to be locked right now (that would
  // silently write unencrypted content into a vault folder).
  if (currentFolderVaultId !== 0 && !(unlockedVault?.vaultId === currentFolderVaultId)) {
    handle.setFailed("This folder is a locked vault - unlock it before uploading.");
    return;
  }
  const vault = currentFolderVaultId !== 0 ? unlockedVault : null;

  try {
    const result = vault
      ? await uploadFileEncrypted(path, file, vault.vaultId, vault.vk, (done, total) =>
          handle.setProgress(done, total),
        )
      : await uploadFile(path, file, (done, total) => handle.setProgress(done, total));
    if (!result.ok) {
      // No partial/corrupt commit is possible here: uploadFile only
      // calls FILE_COMMIT after every chunk has landed, so a mid-upload
      // failure just leaves the file's prior state untouched - retrying
      // is always safe to re-run from scratch.
      handle.setFailed(`Failed: ${result.data.status ?? "error"}`, () => void uploadOne(file));
      return;
    }
    handle.setProgress(file.size, file.size || 1);
    setTimeout(() => handle.remove(), 1500);
    await refreshFileList();
  } catch (err) {
    handle.setFailed(err instanceof Error ? err.message : "Upload failed", () => void uploadOne(file));
  }
}

async function handleDownload(entry: FileEntry): Promise<void> {
  const handle = createTransferItem(`Downloading ${entry.name}`);
  // The entry's own vault_id (TASK-156/TASK-159), not currentFolderVaultId -
  // an encrypted file keeps its vault_id after being moved out of the
  // vault's registered folder, and the folder-level signal would wrongly
  // call it plaintext there.
  if (entry.vault_id !== 0 && !(unlockedVault?.vaultId === entry.vault_id)) {
    handle.setFailed("This file's vault is locked - unlock it before downloading.");
    return;
  }
  const vault = entry.vault_id !== 0 ? unlockedVault : null;
  try {
    const blob = vault
      ? await downloadFileEncrypted(entry.version_id, entry.size_bytes, vault.vk, (done, total) =>
          handle.setProgress(done, total),
        )
      : await downloadFile(entry.version_id, entry.size_bytes, (done, total) =>
          handle.setProgress(done, total),
        );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = entry.name;
    a.click();
    URL.revokeObjectURL(url);
    setTimeout(() => handle.remove(), 1500);
  } catch (err) {
    handle.setFailed(err instanceof Error ? err.message : "Download failed", () =>
      void handleDownload(entry),
    );
  }
}

// ── Version history view (TASK-140) ─────────────────────────────────────

let historyPath = "";

async function enterHistoryView(entry: FileEntry): Promise<void> {
  historyPath = joinPath(currentPath, entry.name);
  historyFileLabel.textContent = entry.name;
  browserView.hidden = true;
  historyView.hidden = false;
  await refreshVersionList();
}

historyBackBtn.addEventListener("click", () => {
  historyView.hidden = true;
  browserView.hidden = false;
});

async function refreshVersionList(): Promise<void> {
  clearError(historyError);
  const result = await listVersions(historyPath);
  if (!result.ok) {
    showError(historyError, `Could not list versions: ${result.data.status ?? "error"}`);
    return;
  }
  renderVersionTable(result.data);
}

function renderVersionTable(entries: VersionEntry[]): void {
  versionTableBody.replaceChildren();
  const sorted = [...entries].sort((a, b) => b.version_id - a.version_id);
  for (const v of sorted) {
    versionTableBody.appendChild(renderVersionRow(v));
  }
}

function renderVersionRow(v: VersionEntry): HTMLTableRowElement {
  const row = document.createElement("tr");

  const idCell = document.createElement("td");
  idCell.textContent = `#${v.version_id}`;
  row.appendChild(idCell);

  const sizeCell = document.createElement("td");
  sizeCell.textContent = formatSize(v.size_bytes);
  row.appendChild(sizeCell);

  const createdCell = document.createElement("td");
  createdCell.textContent = formatMtime(v.created_at);
  row.appendChild(createdCell);

  const actionsCell = document.createElement("td");
  const restoreBtn = document.createElement("button");
  restoreBtn.textContent = "Restore";
  restoreBtn.className = "row-action";
  restoreBtn.addEventListener("click", () => {
    void handleRestoreVersion(v);
  });
  actionsCell.appendChild(restoreBtn);
  row.appendChild(actionsCell);

  return row;
}

async function handleRestoreVersion(v: VersionEntry): Promise<void> {
  if (!window.confirm(`Restore version #${v.version_id} as the new current version?`)) return;
  const result = await restoreVersion(historyPath, v.version_id);
  if (!result.ok) {
    showError(historyError, `Could not restore: ${result.data.status ?? "error"}`);
    return;
  }
  await refreshVersionList();
}

// ── Sharing / public links view (TASK-140) ──────────────────────────────
//
// Security note (carried from TASK-134/140): a link_token is a bearer
// credential. It is shown exactly once, right after creation, in a
// readonly field with an explicit Copy action - never as plain inline
// text left sitting in the page, and never passed to console.log/any
// telemetry (api.ts's own note - this module doesn't log it either).

let shareFileId = 0;

function permissionLabel(p: number): string {
  switch (p) {
    case 1: return "View";
    case 2: return "Edit";
    case 3: return "Owner";
    default: return `#${p}`;
  }
}

async function enterShareView(entry: FileEntry): Promise<void> {
  shareFileId = entry.file_id;
  shareFileLabel.textContent = entry.name;
  browserView.hidden = true;
  shareView.hidden = false;
  linkNewTokenInput.value = "";
  linkNewTokenBox.hidden = true;
  await refreshShareLists();
}

shareBackBtn.addEventListener("click", () => {
  shareView.hidden = true;
  browserView.hidden = false;
  linkNewTokenInput.value = "";
  linkNewTokenBox.hidden = true;
});

async function refreshShareLists(): Promise<void> {
  clearError(shareError);

  const sharesResult = await listShares(0);
  if (sharesResult.ok) {
    renderShareTable(sharesResult.data.filter((s) => s.file_id === shareFileId));
  } else {
    showError(shareError, `Could not list shares: ${sharesResult.data.status ?? "error"}`);
  }

  const linksResult = await listLinks(shareFileId);
  if (linksResult.ok) {
    renderLinkTable(linksResult.data);
  } else {
    showError(shareError, `Could not list links: ${linksResult.data.status ?? "error"}`);
  }
}

function renderShareTable(entries: ShareEntry[]): void {
  shareTableBody.replaceChildren();
  for (const s of entries) {
    shareTableBody.appendChild(renderShareRow(s));
  }
}

function renderShareRow(s: ShareEntry): HTMLTableRowElement {
  const row = document.createElement("tr");

  const userCell = document.createElement("td");
  userCell.textContent = s.target_username;
  row.appendChild(userCell);

  const permCell = document.createElement("td");
  permCell.textContent = permissionLabel(s.permission);
  row.appendChild(permCell);

  const statusCell = document.createElement("td");
  statusCell.textContent = s.revoked ? "Revoked" : "Active";
  row.appendChild(statusCell);

  const actionsCell = document.createElement("td");
  if (!s.revoked) {
    const revokeBtn = document.createElement("button");
    revokeBtn.textContent = "Revoke";
    revokeBtn.className = "row-action";
    revokeBtn.addEventListener("click", () => {
      void handleRevokeShare(s.share_id);
    });
    actionsCell.appendChild(revokeBtn);
  }
  row.appendChild(actionsCell);

  return row;
}

async function handleRevokeShare(shareId: number): Promise<void> {
  const result = await revokeShare(shareId);
  if (!result.ok) {
    showError(shareError, `Could not revoke: ${result.data.status ?? "error"}`);
    return;
  }
  await refreshShareLists();
}

shareGrantBtn.addEventListener("click", () => {
  void handleGrantShare();
});

async function handleGrantShare(): Promise<void> {
  const username = shareUsernameInput.value.trim();
  if (!username) return;
  const permission = Number(sharePermissionSelect.value);

  const result = await grantShare(shareFileId, username, permission);
  if (!result.ok) {
    showError(shareError, `Could not grant access: ${result.data.status ?? "error"}`);
    return;
  }
  shareUsernameInput.value = "";
  await refreshShareLists();
}

function renderLinkTable(entries: LinkEntry[]): void {
  linkTableBody.replaceChildren();
  for (const l of entries) {
    linkTableBody.appendChild(renderLinkRow(l));
  }
}

function renderLinkRow(l: LinkEntry): HTMLTableRowElement {
  const row = document.createElement("tr");

  const nameCell = document.createElement("td");
  nameCell.textContent = `Link #${l.share_id}`;
  row.appendChild(nameCell);

  const permCell = document.createElement("td");
  permCell.textContent = permissionLabel(l.permission);
  row.appendChild(permCell);

  const statusCell = document.createElement("td");
  statusCell.textContent = l.revoked ? "Revoked" : "Active";
  row.appendChild(statusCell);

  const actionsCell = document.createElement("td");
  if (!l.revoked) {
    const revokeBtn = document.createElement("button");
    revokeBtn.textContent = "Revoke";
    revokeBtn.className = "row-action";
    revokeBtn.addEventListener("click", () => {
      void handleRevokeLink(l.share_id);
    });
    actionsCell.appendChild(revokeBtn);
  }
  row.appendChild(actionsCell);

  return row;
}

async function handleRevokeLink(shareId: number): Promise<void> {
  const result = await revokeLink(shareId);
  if (!result.ok) {
    showError(shareError, `Could not revoke link: ${result.data.status ?? "error"}`);
    return;
  }
  await refreshShareLists();
}

linkCreateBtn.addEventListener("click", () => {
  void handleCreateLink();
});

async function handleCreateLink(): Promise<void> {
  const permission = Number(sharePermissionSelect.value);
  const result = await createLink(shareFileId, permission);
  if (!result.ok) {
    showError(shareError, `Could not create link: ${result.data.status ?? "error"}`);
    return;
  }
  // Shown exactly once, per TASK-134/140's "never re-display" convention
  // - not stored anywhere in this module's own state beyond this input's
  // DOM value, which is cleared on Done/navigate-away.
  linkNewTokenInput.value = result.data.link_token;
  linkNewTokenBox.hidden = false;
  await refreshShareLists();
}

linkCopyBtn.addEventListener("click", () => {
  void navigator.clipboard.writeText(linkNewTokenInput.value);
});

linkDismissBtn.addEventListener("click", () => {
  linkNewTokenInput.value = "";
  linkNewTokenBox.hidden = true;
});

// Breadcrumb navigation: clicking the path label goes up one level.
currentPathLabel.addEventListener("click", () => {
  if (currentPath === "/") return;
  const trimmed = currentPath.endsWith("/") ? currentPath.slice(0, -1) : currentPath;
  const lastSlash = trimmed.lastIndexOf("/");
  currentPath = lastSlash <= 0 ? "/" : trimmed.slice(0, lastSlash);
  void refreshFileList();
});
