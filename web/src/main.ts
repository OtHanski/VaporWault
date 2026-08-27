/*
 * main.ts — login view (TASK-137) + file browser view (TASK-138).
 * Single static page, two sections toggled via `hidden`, no router
 * library and no SPA framework (TASK-136's constraint).
 */

import {
  login,
  loginWithOtp,
  logout,
  linkAccess,
  getAccounts,
  setActiveSlot,
  getActiveSlot,
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
  search,
  getNotifyPrefs,
  setNotifyPrefs,
  type FileEntry,
  type VersionEntry,
  type ShareEntry,
  type LinkEntry,
  type AccountSlot,
  type SearchEntry,
} from "./api.js";

// ── Element lookups ─────────────────────────────────────────────────────────

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing element #${id}`);
  return e as T;
}

const loginView = el<HTMLElement>("login-view");
const linkView = el<HTMLElement>("link-view");
const linkAccessForm = el<HTMLFormElement>("link-access-form");
const linkAccessStatus = el<HTMLElement>("link-access-status");
const linkAccessPasswordField = el<HTMLElement>("link-access-password-field");
const linkAccessPasswordInput = el<HTMLInputElement>("link-access-password");
const linkAccessSubmitBtn = el<HTMLButtonElement>("link-access-submit-btn");
const linkAccessError = el<HTMLElement>("link-access-error");
const browserView = el<HTMLElement>("browser-view");
const loginForm = el<HTMLFormElement>("login-form");
const usernameInput = el<HTMLInputElement>("login-username");
const passwordInput = el<HTMLInputElement>("login-password");
const otpField = el<HTMLElement>("otp-field");
const otpInput = el<HTMLInputElement>("login-otp");
const rememberCheckbox = el<HTMLInputElement>("login-remember");
const loginCancelBtn = el<HTMLButtonElement>("login-cancel-btn");
const loginError = el<HTMLElement>("login-error");
const accountSwitcher = el<HTMLElement>("account-switcher");
const logoutBtn = el<HTMLButtonElement>("logout-btn");
const mkdirBtn = el<HTMLButtonElement>("mkdir-btn");
const currentPathLabel = el<HTMLElement>("current-path");
const fileTableBody = el<HTMLTableSectionElement>("file-table-body");
const browserError = el<HTMLElement>("browser-error");
const uploadBtn = el<HTMLButtonElement>("upload-btn");
const uploadInput = el<HTMLInputElement>("upload-input");
const transferList = el<HTMLUListElement>("transfer-list");
const vaultCreateBtn = el<HTMLButtonElement>("vault-create-btn");
const searchInput = el<HTMLInputElement>("search-input");
const searchClearBtn = el<HTMLButtonElement>("search-clear-btn");
const searchStatus = el<HTMLElement>("search-status");
const vaultBanner = el<HTMLElement>("vault-banner");
const vaultBannerText = el<HTMLElement>("vault-banner-text");
const vaultUnlockBtn = el<HTMLButtonElement>("vault-unlock-btn");
const vaultLockBtn = el<HTMLButtonElement>("vault-lock-btn");

const historyView = el<HTMLElement>("history-view");
const historyFileLabel = el<HTMLElement>("history-file-label");
const historyBackBtn = el<HTMLButtonElement>("history-back-btn");
const versionTableBody = el<HTMLTableSectionElement>("version-table-body");
const historyError = el<HTMLElement>("history-error");

const settingsBtn = el<HTMLButtonElement>("settings-btn");
const settingsView = el<HTMLElement>("settings-view");
const settingsBackBtn = el<HTMLButtonElement>("settings-back-btn");
const notifyPrefsList = el<HTMLElement>("notify-prefs-list");
const settingsError = el<HTMLElement>("settings-error");

const shareView = el<HTMLElement>("share-view");
const shareFileLabel = el<HTMLElement>("share-file-label");
const shareBackBtn = el<HTMLButtonElement>("share-back-btn");
const shareUsernameInput = el<HTMLInputElement>("share-username");
const sharePermissionSelect = el<HTMLSelectElement>("share-permission");
const shareGrantBtn = el<HTMLButtonElement>("share-grant-btn");
const shareTableBody = el<HTMLTableSectionElement>("share-table-body");
const linkCreateBtn = el<HTMLButtonElement>("link-create-btn");
const linkExpiryCheck = el<HTMLInputElement>("link-expiry-check");
const linkExpiryDays = el<HTMLInputElement>("link-expiry-days");
const linkPasswordCheck = el<HTMLInputElement>("link-password-check");
const linkPasswordInput = el<HTMLInputElement>("link-password");
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

// ── Multi-account state (TASK-166) ──────────────────────────────────────
//
// `accounts` mirrors the gateway's own per-slot state (GET-like
// /api/accounts, scoped to this browser's own cookies) — refreshed after
// every login/logout so the switcher never shows stale slots. Only the
// ACTIVE slot number itself (never anything sensitive - not a username,
// not a token) is persisted, in localStorage, purely so a page reload
// restores the same slot the user was last looking at rather than always
// falling back to "the first occupied one" (TASK-166's own "last-active"
// acceptance wording).

let accounts: AccountSlot[] = [];
const LAST_SLOT_STORAGE_KEY = "vw_active_slot";

function saveLastSlot(slot: number): void {
  try {
    localStorage.setItem(LAST_SLOT_STORAGE_KEY, String(slot));
  } catch {
    // Private-browsing/storage-disabled: losing the "remembered" active
    // slot across reloads is a minor UX papercut, not a functional
    // failure worth surfacing to the user.
  }
}

function loadLastSlot(): number | null {
  try {
    const raw = localStorage.getItem(LAST_SLOT_STORAGE_KEY);
    return raw === null ? null : Number(raw);
  } catch {
    return null;
  }
}

async function refreshAccounts(): Promise<void> {
  const result = await getAccounts();
  accounts = result.ok ? result.data.slots : [];
  renderAccountSwitcher();
}

function renderAccountSwitcher(): void {
  accountSwitcher.replaceChildren();
  const active = getActiveSlot();

  for (const acct of accounts) {
    const pill = document.createElement("button");
    pill.type = "button";
    pill.className = "account-pill" + (acct.slot === active ? " active" : "");
    // Empty username = a redeemed public-link session (vw_gateway_
    // session_create's NULL-username convention) - this UI never
    // actually reaches that case today (link redemption has its own
    // flow, not this switcher), but label it sensibly rather than
    // showing a blank pill if it ever does.
    pill.textContent = acct.username || "(shared link)";
    pill.addEventListener("click", () => {
      if (acct.slot !== getActiveSlot()) void switchToSlot(acct.slot);
    });
    accountSwitcher.appendChild(pill);
  }

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "account-pill add-account";
  addBtn.textContent = "+ Add account";
  addBtn.addEventListener("click", () => {
    showLoginView({ cancelable: accounts.length > 0 });
  });
  accountSwitcher.appendChild(addBtn);
}

async function switchToSlot(slot: number): Promise<void> {
  setActiveSlot(slot);
  saveLastSlot(slot);
  await enterBrowserView();
}

// Shows the login form. `cancelable` controls the Cancel button: adding
// a second account (already-open browser view behind it) can back out
// without submitting; the very first login (no accounts open yet) has
// nothing to cancel back to.
function showLoginView(opts: { cancelable: boolean }): void {
  forgetPendingCredentials();
  usernameInput.value = "";
  passwordInput.value = "";
  rememberCheckbox.checked = false;
  clearError(loginError);
  loginCancelBtn.hidden = !opts.cancelable;
  browserView.hidden = true;
  historyView.hidden = true;
  shareView.hidden = true;
  settingsView.hidden = true;
  loginView.hidden = false;
  usernameInput.focus();
}

loginCancelBtn.addEventListener("click", () => {
  // Fully abandon whatever was in progress - including a mid-2FA
  // attempt's pending username/password sitting in module state, which
  // would otherwise survive until the next login attempt overwrites or
  // clears it.
  forgetPendingCredentials();
  passwordInput.value = "";
  void enterBrowserView();
});

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
  // No explicit `slot` here - the gateway always picks the next free one
  // (vw_gateway_api.c's resolve_login_slot), matching this form's only
  // two real callers: the very first login (slot 0, trivially "next
  // free") and "+ Add account" (this task's own note that it "targets
  // the next free slot rather than replacing the current one").
  const opts = { remember: rememberCheckbox.checked };

  // Snapshot BEFORE the request - used below to find which slot this
  // login just landed in, since the gateway's own response never says
  // (the slot is only visible as a Set-Cookie name, which JS can't read -
  // it's HttpOnly).
  const previousSlots = new Set(accounts.map((a) => a.slot));

  const result = otpVisible
    ? await loginWithOtp(username, password, otpInput.value, opts)
    : await login(username, password, opts);

  if (result.ok) {
    forgetPendingCredentials();
    passwordInput.value = "";
    await refreshAccounts();
    const newAccount = accounts.find((a) => !previousSlots.has(a.slot));
    setActiveSlot(newAccount?.slot ?? accounts[0]?.slot ?? 0);
    saveLastSlot(getActiveSlot());
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
  // Logs out only the currently-active slot (api.ts's logout() defaults
  // to getActiveSlot()) - other open accounts in this same browser must
  // be unaffected, matching TASK-164's own multi-slot isolation
  // guarantee at the UI layer too.
  await logout();
  await refreshAccounts();
  if (accounts.length > 0) {
    setActiveSlot(accounts[0].slot);
    saveLastSlot(getActiveSlot());
    await enterBrowserView();
    return;
  }
  showLoginView({ cancelable: false });
}

// ── File browser view (TASK-138) ────────────────────────────────────────

async function enterBrowserView(): Promise<void> {
  loginView.hidden = true;
  browserView.hidden = false;
  // Defensive, not just for the login path: switchToSlot() can be
  // triggered from the history/share views too (the switcher pills are
  // only rendered inside browser-view's header today, but nothing stops
  // that from changing later) - without this, switching slots while
  // looking at either would leave TWO sections visible at once, since
  // neither of those views' own "Back" buttons run here to hide
  // themselves.
  linkView.hidden = true;
  historyView.hidden = true;
  shareView.hidden = true;
  settingsView.hidden = true;
  renderAccountSwitcher();
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
  // Any real "list this directory" action (folder click, up-navigation,
  // mkdir's own refresh, initial load) implicitly leaves search mode -
  // otherwise the search box could keep showing stale text/results while
  // the table underneath silently became a normal directory listing.
  clearSearchState();
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

// ── Search (TASK-198/199/201; docs/PROTOCOL.md §7.12) ───────────────────
//
// Debounced client-side (fires performSearch() only after typing pauses,
// not per keystroke) - there's no separate "async vs sync" concern here
// the way TASK-200's GUI correction had to work through: every fetch()
// call in this file is already async/non-blocking by the nature of the
// browser event loop, so debouncing is purely about not spamming the
// gateway with one request per character.
//
// Results reuse file-table-body directly rather than a second table -
// same "shown in place of the normal directory listing" shape as
// TASK-200's GUI version. Actions are deliberately narrower than a normal
// directory row's: SEARCH_RESP carries no virtual path and no version_id
// (see §7.12's own rationale), so only Share (file_id + name is all
// enterShareView needs) is wired up here - Download/History/Rename/
// Delete/folder-navigation would need either a path or a version_id this
// response doesn't have, and adding a new round-trip just to resolve one
// wasn't worth it for what search is actually for (finding a file, then
// acting on it after navigating to its real location).
const SEARCH_DEBOUNCE_MS = 350;
let searchDebounceTimer: number | undefined;

function clearSearchState(): void {
  searchInput.value = "";
  searchClearBtn.hidden = true;
  clearError(searchStatus);
  if (searchDebounceTimer !== undefined) {
    window.clearTimeout(searchDebounceTimer);
    searchDebounceTimer = undefined;
  }
}

function showSearchStatus(message: string, isError: boolean): void {
  searchStatus.textContent = message;
  searchStatus.className = isError ? "error" : "note";
  searchStatus.hidden = false;
}

searchInput.addEventListener("input", () => {
  if (searchDebounceTimer !== undefined) window.clearTimeout(searchDebounceTimer);
  const query = searchInput.value;
  if (query === "") {
    clearSearchState();
    void refreshFileList();
    return;
  }
  searchDebounceTimer = window.setTimeout(() => {
    void performSearch(query);
  }, SEARCH_DEBOUNCE_MS);
});

searchClearBtn.addEventListener("click", () => {
  clearSearchState();
  void refreshFileList();
});

async function performSearch(query: string): Promise<void> {
  clearError(browserError);
  searchClearBtn.hidden = false;
  clearError(searchStatus);

  const result = await search(query);
  if (!result.ok) {
    fileTableBody.replaceChildren();
    showSearchStatus(`Search failed: ${result.data.status ?? "error"}`, true);
    return;
  }

  renderSearchTable(result.data.results);
  if (result.data.results.length === 0) {
    showSearchStatus("No matches.", false);
  } else if (result.data.truncated) {
    showSearchStatus("More matches exist than shown - narrow your search.", false);
  }
}

function renderSearchTable(entries: SearchEntry[]): void {
  fileTableBody.replaceChildren();
  const sorted = [...entries].sort((a, b) => {
    if (a.is_dir !== b.is_dir) return b.is_dir - a.is_dir; // folders first
    return a.name.localeCompare(b.name);
  });
  for (const entry of sorted) {
    fileTableBody.appendChild(renderSearchRow(entry));
  }
}

function renderSearchRow(entry: SearchEntry): HTMLTableRowElement {
  const row = document.createElement("tr");
  const isDir = entry.is_dir !== 0;

  const nameCell = document.createElement("td");
  // textContent, never innerHTML - same XSS-safety rule as renderFileRow:
  // a search result can be a file someone else named, shared with this
  // account, and must never be interpreted as markup.
  const nameSpan = document.createElement("span");
  const lockPrefix = !isDir && entry.vault_id !== 0 ? "\u{1F512} " : "";
  const sharedSuffix = entry.is_shared !== 0 ? " (shared)" : "";
  nameSpan.textContent =
    lockPrefix + (isDir ? "\u{1F4C1} " : "\u{1F4C4} ") + entry.name + sharedSuffix;
  nameCell.appendChild(nameSpan);
  row.appendChild(nameCell);

  const sizeCell = document.createElement("td");
  sizeCell.textContent = isDir ? "-" : formatSize(entry.size_bytes);
  row.appendChild(sizeCell);

  const mtimeCell = document.createElement("td");
  mtimeCell.textContent = isDir ? "-" : formatMtime(entry.mtime_unix);
  row.appendChild(mtimeCell);

  const actionsCell = document.createElement("td");
  const shareBtn = document.createElement("button");
  shareBtn.textContent = "Share";
  shareBtn.className = "row-action";
  shareBtn.addEventListener("click", () => {
    void enterShareView(entry);
  });
  actionsCell.appendChild(shareBtn);
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

// Only file_id/name are ever read here - narrowed (rather than FileEntry)
// so a SearchEntry (TASK-201, no virtual path) can open this view too.
async function enterShareView(entry: { file_id: number; name: string }): Promise<void> {
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

// ── Settings view: notification preferences (TASK-206/207/211) ─────────────
// Thin passthrough on the gateway (docs/PROTOCOL.md §7.13) - the bit
// table below mirrors vapourwault-cli's NOTIFY_CATEGORIES[] and the
// desktop GUI's own copy (TASK-209/210) exactly, so all three surfaces
// describe the same four categories identically.
const NOTIFY_CATEGORIES: { name: string; bit: number; label: string; desc: string }[] = [
  { name: "share_received", bit: 0x0001, label: "Someone shares something with me",
    desc: "A grant or link naming you was created" },
  { name: "quota_warning", bit: 0x0002, label: "My storage usage crosses 90% of quota",
    desc: "Re-arms once usage drops back under the threshold" },
  { name: "new_login", bit: 0x0004, label: "A new login succeeds on my account",
    desc: "Never fires for a normal reconnect" },
  { name: "account_security_change", bit: 0x0008, label: "My password or 2FA setting changes",
    desc: "Password change or 2FA enable/disable" },
];

async function enterSettingsView(): Promise<void> {
  browserView.hidden = true;
  settingsView.hidden = false;
  await refreshNotifyPrefs();
}

settingsBtn.addEventListener("click", () => { void enterSettingsView(); });

settingsBackBtn.addEventListener("click", () => {
  settingsView.hidden = true;
  browserView.hidden = false;
});

async function refreshNotifyPrefs(): Promise<void> {
  clearError(settingsError);
  const result = await getNotifyPrefs();
  if (!result.ok) {
    showError(settingsError, `Could not load notification preferences: ${result.data.status ?? "error"}`);
    return;
  }
  renderNotifyPrefs(result.data.prefs);
}

function renderNotifyPrefs(prefs: number): void {
  notifyPrefsList.replaceChildren();
  for (const cat of NOTIFY_CATEGORIES) {
    const label = document.createElement("label");
    label.className = "checkbox-field";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = (prefs & cat.bit) !== 0;
    checkbox.addEventListener("change", () => { void toggleNotifyCategory(cat, checkbox); });

    const text = document.createElement("span");
    text.textContent = cat.label;

    const note = document.createElement("span");
    note.className = "note";
    note.textContent = `(${cat.desc})`;

    label.appendChild(checkbox);
    label.appendChild(text);
    label.appendChild(note);
    notifyPrefsList.appendChild(label);
  }
}

async function toggleNotifyCategory(
  cat: { name: string; bit: number },
  checkbox: HTMLInputElement,
): Promise<void> {
  clearError(settingsError);
  // Read-modify-write against the server's current value, not the
  // locally-displayed one - the same pattern vapourwault-cli's `notify
  // set` and the desktop GUI's settings panel both use (§7.13's own
  // documented "SET replaces the complete bitmask" contract).
  const current = await getNotifyPrefs();
  if (!current.ok) {
    showError(settingsError, `Could not load current preferences: ${current.data.status ?? "error"}`);
    checkbox.checked = !checkbox.checked; // revert the optimistic toggle
    return;
  }
  const requested = checkbox.checked ? (current.data.prefs | cat.bit) : (current.data.prefs & ~cat.bit);
  const result = await setNotifyPrefs(requested);
  if (!result.ok) {
    showError(settingsError, `Could not update notification setting: ${result.data.status ?? "error"}`);
    checkbox.checked = !checkbox.checked;
    return;
  }
  // Re-render from the ACK's echoed value, never assumed - mirrors the
  // desktop GUI's own "never assume the write applied" handling.
  renderNotifyPrefs(result.data.prefs);
}

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

  const passwordCell = document.createElement("td");
  passwordCell.textContent = l.has_password ? "Yes" : "No";
  row.appendChild(passwordCell);

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

linkExpiryCheck.addEventListener("change", () => {
  linkExpiryDays.disabled = !linkExpiryCheck.checked;
});
linkPasswordCheck.addEventListener("change", () => {
  linkPasswordInput.disabled = !linkPasswordCheck.checked;
  if (!linkPasswordCheck.checked) linkPasswordInput.value = "";
});

linkCreateBtn.addEventListener("click", () => {
  void handleCreateLink();
});

async function handleCreateLink(): Promise<void> {
  const permission = Number(sharePermissionSelect.value);
  // expiresAt (TASK-190): the gateway API already accepted this
  // parameter (`api.ts`'s createLink) before this task — the form
  // itself never surfaced a way to set it. password is new end-to-end
  // (TASK-186-190).
  const expiresAt = linkExpiryCheck.checked
    ? Math.floor(Date.now() / 1000) + Number(linkExpiryDays.value || "1") * 86400
    : 0;
  const password = linkPasswordCheck.checked ? linkPasswordInput.value : "";
  const result = await createLink(shareFileId, permission, expiresAt, password);
  // Never let a typed password linger in the DOM longer than the request
  // that used it, success or failure.
  linkPasswordInput.value = "";
  linkPasswordCheck.checked = false;
  linkPasswordInput.disabled = true;
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

// ── Public link redemption (TASK-134/186; frontend: TASK-216) ────────────
//
// URL shape: a query parameter (?link=<64-hex-char token>), not a path
// segment - nginx serves this frontend as a static, SPA-less page with no
// server-side routing at all (CLAUDE.md's WEB.09 constraint: "nginx ...
// reverse-proxies /api/* ... [this frontend needs] no server-side
// routing change"). A query parameter needs none either; a path segment
// would need nginx to rewrite unknown paths back to index.html, which
// isn't configured today. The token is stripped from the URL immediately
// (history.replaceState, before any redemption attempt) purely as
// hygiene - once used it doesn't need to keep sitting in the address bar
// or browser history, though the link itself is still just as usable
// again from a fresh copy of the original URL.
//
// The password is NEVER put in the URL, ever - only the token, in a
// query param; a password (when the link needs one) is collected only
// via this view's own password field and sent as a POST body, same as
// every other password in this frontend (TASK-190's create-link form
// already established this same rule for the other direction).
//
// Product decision on VIEW vs EDIT scope, recorded here per TASK-216's
// own note that this needed one rather than being assumed: once
// redemption succeeds, the browser view is reused COMPLETELY UNCHANGED,
// with no client-side hiding or graying-out of actions based on the
// link's permission level. This matches how this frontend already
// treats an ordinary VIEW-only share grant everywhere else - there is no
// existing precedent anywhere in this codebase for a client-side
// permission-shaped UI, only server-side enforcement with a clean error
// message on an action the caller's effective_permission() doesn't
// allow (e.g. handleDelete's showError path). Introducing client-side
// scoping just for link sessions specifically would be a new, one-off
// pattern rather than consistency with the rest of the app. Recorded in
// ARCHITECTURE.md's Decision Log alongside this note.

function getLinkTokenFromUrl(): string | null {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("link");
  if (!token) return null;
  params.delete("link");
  const rest = params.toString();
  const newUrl = window.location.pathname + (rest ? `?${rest}` : "") + window.location.hash;
  window.history.replaceState(null, "", newUrl);
  return token;
}

let pendingLinkToken: string | null = null;

function showLinkView(): void {
  loginView.hidden = true;
  browserView.hidden = true;
  linkView.hidden = false;
}

async function attemptLinkAccess(token: string, password: string): Promise<void> {
  clearError(linkAccessError);
  linkAccessStatus.textContent = "Opening shared link...";
  linkAccessSubmitBtn.hidden = true;

  // Captured before the call, not assumed from array position afterward:
  // this call never passes its own `slot` option, so the gateway picks
  // whichever slot resolve_login_slot considers "next free" - not
  // necessarily the highest-numbered one if a lower slot was freed by an
  // earlier logout, which would make "last element of the accounts
  // array" (if it happens to be sorted by slot number) the wrong guess.
  // Diffing the before/after slot sets is correct regardless of gaps or
  // sort order.
  const slotsBefore = new Set(accounts.map((a) => a.slot));
  const result = await linkAccess(token, password ? { password } : {});
  if (result.ok) {
    pendingLinkToken = null;
    await refreshAccounts();
    const added = accounts.find((a) => !slotsBefore.has(a.slot));
    if (added) {
      setActiveSlot(added.slot);
      saveLastSlot(added.slot);
    }
    linkView.hidden = true;
    await enterBrowserView();
    return;
  }

  if (result.data.status === "link_password_required") {
    linkAccessStatus.textContent = "This link requires a password.";
    linkAccessPasswordField.hidden = false;
    linkAccessSubmitBtn.hidden = false;
    linkAccessPasswordInput.focus();
    return;
  }
  if (result.data.status === "link_password_wrong") {
    linkAccessStatus.textContent = "This link requires a password.";
    linkAccessPasswordField.hidden = false;
    linkAccessSubmitBtn.hidden = false;
    linkAccessPasswordInput.value = "";
    linkAccessPasswordInput.focus();
    showError(linkAccessError, "Wrong password.");
    return;
  }
  if (result.data.status === "no_free_slot") {
    // Distinct from "the link itself is bad" - this browser already has
    // every account slot occupied. Not the link's fault, so not worded
    // as if it were.
    linkAccessStatus.textContent = "Too many accounts are already open in this browser.";
    showError(linkAccessError, "Log out of one first, then reopen this link.");
    return;
  }
  linkAccessStatus.textContent = "This link could not be opened.";
  showError(linkAccessError, "It may be invalid, expired, or revoked.");
}

linkAccessForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  if (!pendingLinkToken) return;
  void attemptLinkAccess(pendingLinkToken, linkAccessPasswordInput.value);
});

// ── Bootstrap (TASK-166) ─────────────────────────────────────────────────
//
// index.html's own default markup shows login-view and hides
// browser-view - correct for "no session at all" and left as-is here.
// This is what actually fixes the pre-existing gap this task's own
// design note flagged: previously the login form always rendered first
// on every page load, even with a still-valid remembered/live session
// cookie already present, because nothing ever checked. /api/accounts
// works here as a plain "does this browser have anything to resume"
// probe - it needs no request body and returns an empty list rather
// than a 401 when nothing is live, so this is safe to call
// unconditionally before the user has done anything.
async function init(): Promise<void> {
  const linkToken = getLinkTokenFromUrl();
  if (linkToken) {
    pendingLinkToken = linkToken;
    showLinkView();
    await attemptLinkAccess(linkToken, "");
    return;
  }

  await refreshAccounts();
  if (accounts.length === 0) return;

  const lastSlot = loadLastSlot();
  const target = accounts.find((a) => a.slot === lastSlot) ?? accounts[0];
  setActiveSlot(target.slot);
  saveLastSlot(target.slot);
  await enterBrowserView();
}

void init();
