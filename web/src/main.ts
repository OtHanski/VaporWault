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
  uploadFile,
  downloadFile,
  type FileEntry,
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

// ── State ────────────────────────────────────────────────────────────────
//
// Username/password are kept in memory ONLY for the duration of the 2FA
// round trip (initial submit -> "otp_required" -> resubmit with the code)
// - never persisted (localStorage/sessionStorage), matching TASK-137's
// scope note. Cleared immediately on either success or final failure.

let pendingUsername: string | null = null;
let pendingPassword: string | null = null;
let currentPath = "/";

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
  nameLink.textContent = (isDir ? "\u{1F4C1} " : "\u{1F4C4} ") + entry.name;
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
  }
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

  const result = await mkdir(name);
  if (!result.ok) {
    showError(browserError, `Could not create "${name}": ${result.data.status ?? "error"}`);
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
  try {
    const result = await uploadFile(path, file, (done, total) => handle.setProgress(done, total));
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
  try {
    const blob = await downloadFile(entry.version_id, entry.size_bytes, (done, total) =>
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

// Breadcrumb navigation: clicking the path label goes up one level.
currentPathLabel.addEventListener("click", () => {
  if (currentPath === "/") return;
  const trimmed = currentPath.endsWith("/") ? currentPath.slice(0, -1) : currentPath;
  const lastSlash = trimmed.lastIndexOf("/");
  currentPath = lastSlash <= 0 ? "/" : trimmed.slice(0, lastSlash);
  void refreshFileList();
});
