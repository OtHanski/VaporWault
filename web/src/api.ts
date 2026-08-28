/*
 * api.ts — thin fetch() wrapper over the gateway's /api/* endpoints
 * (TASK-136/137/138). No framework, no build-time dependency beyond the
 * TypeScript compiler itself (tsc output ships as plain JS - see
 * package.json).
 *
 * The gateway session cookie is HttpOnly (set by the server, TASK-132) -
 * this module never reads or stores it directly; `credentials:
 * "same-origin"` is what makes the browser attach it automatically on
 * every request, matching nginx serving this page and proxying /api/*
 * from the same origin (docs/DEPLOYMENT.md).
 *
 * Multi-slot sessions (TASK-164/166): the browser can hold several
 * concurrently-logged-in accounts, each under its own gateway-issued
 * cookie (vw_session_0..vw_session_5) - all of them get attached to
 * every request automatically (they're all just cookies matching the
 * same path), so the ONLY thing this module needs to track client-side
 * is which slot a given request is FOR, sent as the X-Vw-Slot header
 * (vw_gateway_api.c's require_session). setActiveSlot()/getActiveSlot()
 * hold that as simple module state, exactly like currentPath is
 * main.ts's own module state - no per-call parameter threaded through
 * every one of this file's exported functions, since main.ts only ever
 * has one slot "on screen" at a time (switching slots re-fetches
 * everything for the newly active one, see main.ts's switchToSlot).
 */

let activeSlot = 0;

export function setActiveSlot(slot: number): void {
  activeSlot = slot;
}

export function getActiveSlot(): number {
  return activeSlot;
}

export interface FileEntry {
  name: string;
  entry_type: number; // 0 = file, 1 = folder
  file_id: number;
  size_bytes: number;
  mtime_unix: number;
  version_id: number;
  vault_id: number;
}

export interface StatusResponse {
  status: string;
}

export interface VersionEntry {
  version_id: number;
  created_at: number;
  size_bytes: number;
}

// permission: 1 = VIEW, 2 = EDIT, 3 = OWNER (vw_perm_t, docs/PROTOCOL.md).
export interface ShareEntry {
  share_id: number;
  file_id: number;
  share_type: number; // 0 = user grant, 1 = public link
  target_username: string;
  permission: number;
  created_at: number;
  expires_at: number;
  revoked: boolean;
}

export interface LinkEntry {
  share_id: number;
  file_id: number;
  name: string;
  permission: number;
  created_at: number;
  expires_at: number;
  revoked: boolean;
  has_password: boolean;
}

/*
 * A successful response's body is the endpoint's own T; every error
 * response (any non-2xx status) is always {"status": "..."} shaped
 * (vw_gateway_api.c's send_error/send_file_op_error - see TASK-132/133).
 * Modeled as a discriminated union on `ok` so callers get real
 * compile-time checking instead of an unsound "data: T" that lies about
 * the error case's actual shape.
 */
export type ApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; data: StatusResponse };

async function apiPost<T>(path: string, body: unknown): Promise<ApiResult<T>> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Vw-Slot": String(activeSlot) },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  if (res.ok) {
    const data = (await res.json()) as T;
    return { ok: true, status: res.status, data };
  }
  const data = (await res.json()) as StatusResponse;
  return { ok: false, status: res.status, data };
}

/*
 * login/loginWithOtp/link access (TASK-164/165): `slot` targets a
 * specific slot (re-authenticate) - omit to let the gateway pick the
 * next free one ("add account"), the only mode main.ts actually uses.
 * `remember` opts into surviving a gateway restart (TASK-165) - omit or
 * false for today's session-only behavior; silently a no-op if the
 * gateway wasn't started with --state-dir (vw_gateway_api.c's own
 * opt-in framing, this module doesn't need to know which).
 */
export interface LoginOpts {
  slot?: number;
  remember?: boolean;
}

export function login(
  username: string,
  password: string,
  opts: LoginOpts = {},
): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/login", { username, password, ...opts });
}

export function loginWithOtp(
  username: string,
  password: string,
  otp: string,
  opts: LoginOpts = {},
): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/login", { username, password, otp, ...opts });
}

// slot: which slot to log out (defaults to the currently active one, NOT
// always 0 - logging out must never silently act on the wrong account).
export function logout(slot: number = activeSlot): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/logout", { slot });
}

// Redeems a public link (TASK-134/186; frontend: TASK-216). Establishes a
// real gateway session cookie for a new slot, exactly like login - the
// browser then uses every other /api/* endpoint completely unchanged,
// scoped server-side to whatever the link's own permission allows.
// password: omit/empty if the link has none. slot: explicit target slot,
// or omit to let the gateway pick the next free one (the only mode the
// frontend's own redemption flow actually uses - see enterLinkView).
export interface LinkAccessOpts {
  password?: string;
  slot?: number;
}

export function linkAccess(
  linkToken: string,
  opts: LinkAccessOpts = {},
): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/links/access", { link_token: linkToken, ...opts });
}

export interface AccountSlot {
  slot: number;
  username: string; // "" for a redeemed public-link session (no real user)
}

export interface AccountsResponse {
  slots: AccountSlot[];
}

// Deliberately does not go through apiPost: /api/accounts reports every
// occupied slot for THIS browser regardless of X-Vw-Slot (it isn't
// scoped to one slot the way every other endpoint is), so sending that
// header would be misleading about what this call actually means.
export async function getAccounts(): Promise<ApiResult<AccountsResponse>> {
  const res = await fetch("/api/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({}),
  });
  if (res.ok) {
    const data = (await res.json()) as AccountsResponse;
    return { ok: true, status: res.status, data };
  }
  const data = (await res.json()) as StatusResponse;
  return { ok: false, status: res.status, data };
}

export function listFiles(path: string, recursive = false): Promise<ApiResult<FileEntry[]>> {
  return apiPost("/api/files/list", { path, recursive });
}

// Filename search (TASK-198/199/201; docs/PROTOCOL.md §7.12). No virtual
// path field - see that section's own rationale (a match's path isn't
// always meaningful, e.g. a shared item outside the caller's namespace).
export interface SearchEntry {
  name: string;
  file_id: number;
  is_dir: number; // 0 = file, 1 = folder - same convention as FileEntry.entry_type
  size_bytes: number;
  mtime_unix: number;
  vault_id: number;
  is_shared: number; // 1 = visible via a grant, not owned
}

export interface SearchResponse {
  truncated: boolean;
  results: SearchEntry[];
}

export function search(query: string): Promise<ApiResult<SearchResponse>> {
  return apiPost("/api/search", { query });
}

// Notification preferences (TASK-206/207/211; docs/PROTOCOL.md §7.13).
// Thin passthrough, matching the gateway's own posture: `prefs` is the
// raw VW_NOTIFY_* bitmask, decoded/re-encoded client-side against
// NOTIFY_CATEGORIES below (mirrors vapourwault-cli's and the desktop
// GUI's own local category tables - see main.ts).
export interface NotifyPrefsResponse {
  prefs: number;
}

export function getNotifyPrefs(): Promise<ApiResult<NotifyPrefsResponse>> {
  return apiPost("/api/notify/prefs", {});
}

export function setNotifyPrefs(prefs: number): Promise<ApiResult<NotifyPrefsResponse>> {
  return apiPost("/api/notify/prefs/set", { prefs });
}

// Account self-service email (TASK-222; docs/PROTOCOL.md §7.14) - the
// first real path that can put an email on an account, since neither
// account creation nor invite redemption ever ask for one. Needed for
// password recovery and for the notification categories above to ever
// actually fire.
export interface AccountEmailResponse {
  email: string; // "" if no email is on file
}

export function getAccountEmail(): Promise<ApiResult<AccountEmailResponse>> {
  return apiPost("/api/account/email", {});
}

export function setAccountEmail(email: string): Promise<ApiResult<AccountEmailResponse>> {
  return apiPost("/api/account/email/set", { email });
}

// Account self-service two-factor enrollment (TASK-219; docs/PROTOCOL.md
// §7.15). Enabling/disabling requires the current password - a
// security-sensitive toggle, not a preference.
export interface Account2faResponse {
  enabled: boolean;
}

export function getAccount2fa(): Promise<ApiResult<Account2faResponse>> {
  return apiPost("/api/account/2fa", {});
}

export function setAccount2fa(
  password: string,
  enable: boolean,
): Promise<ApiResult<Account2faResponse>> {
  return apiPost("/api/account/2fa/set", { password, enable });
}

export function mkdir(name: string, parentDirId = 0): Promise<ApiResult<{ dir_id: number }>> {
  return apiPost("/api/files/mkdir", { name, parent_dir_id: parentDirId });
}

export function filesStat(path: string): Promise<ApiResult<FileEntry>> {
  return apiPost("/api/files/stat", { path });
}

export function deleteFile(path: string): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/files/delete", { path });
}

export function moveFile(
  fileId: number,
  newName?: string,
  newParentDirId = 0,
): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/files/move", {
    file_id: fileId,
    new_name: newName ?? "",
    new_parent_dir_id: newParentDirId,
  });
}

/*
 * Chunk transfer (TASK-139): the browser drives CHUNK_UPLOAD/FILE_COMMIT
 * and VERSION_CHUNKS/CHUNK_DOWNLOAD_REQ directly, one HTTP request per
 * chunk (gateway side: TASK-133's addendum) - this is what gives real
 * per-file byte progress without any status-polling API. Hashing uses
 * the browser's native SubtleCrypto (no crypto library needed for
 * plaintext SHA-256).
 */

const CHUNK_SIZE = 4 * 1024 * 1024; // matches VW_CHUNK_SIZE_DEFAULT (docs/PROTOCOL.md)

export interface ChunkListResponse {
  chunk_hashes: string[];
  vault_id: number;
  wrapped_dek: string | null;
}

export interface CommitResponse {
  file_id: number;
  version_id: number;
}

function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bufToHex(digest);
}

async function uploadChunk(hash: string, data: ArrayBuffer): Promise<ApiResult<StatusResponse>> {
  const res = await fetch("/api/chunks/upload", {
    method: "POST",
    headers: { "X-Vw-Chunk-Hash": hash, "X-Vw-Slot": String(activeSlot) },
    credentials: "same-origin",
    body: data,
  });
  const data2 = (await res.json()) as StatusResponse;
  return res.ok
    ? { ok: true, status: res.status, data: data2 }
    : { ok: false, status: res.status, data: data2 };
}

async function downloadChunk(hash: string): Promise<ArrayBuffer> {
  const res = await fetch("/api/chunks/download", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Vw-Slot": String(activeSlot) },
    credentials: "same-origin",
    body: JSON.stringify({ hash }),
  });
  if (!res.ok) {
    const body = (await res.json()) as StatusResponse;
    throw new Error(`chunk download failed: ${body.status}`);
  }
  return res.arrayBuffer();
}

export function commitFile(opts: {
  path?: string;
  fileId?: number;
  leafName?: string;
  logicalSize: number;
  chunkHashes: string[];
  // Vault-encrypted commit (TASK-141): both present together, or neither.
  vaultId?: number;
  wrappedDekHex?: string;
}): Promise<ApiResult<CommitResponse>> {
  const body: Record<string, unknown> = {
    logical_size: opts.logicalSize,
    chunk_hashes: opts.chunkHashes,
  };
  if (opts.path) body.path = opts.path;
  if (opts.fileId !== undefined) body.file_id = opts.fileId;
  if (opts.leafName) body.leaf_name = opts.leafName;
  if (opts.vaultId) {
    body.vault_id = opts.vaultId;
    body.wrapped_dek = opts.wrappedDekHex;
  }
  return apiPost("/api/files/commit", body);
}

export function getVersionChunks(versionId: number): Promise<ApiResult<ChunkListResponse>> {
  return apiPost("/api/versions/chunks", { version_id: versionId });
}

export type ProgressCb = (bytesDone: number, bytesTotal: number) => void;

/* Uploads file to `path`, chunk by chunk, reporting cumulative byte
 * progress. Fails cleanly (returns the failing chunk's error, uploads
 * nothing further) rather than committing a partial file. */
export async function uploadFile(
  path: string,
  file: File,
  onProgress?: ProgressCb,
): Promise<ApiResult<CommitResponse>> {
  const totalSize = file.size;
  const chunkHashes: string[] = [];
  let bytesDone = 0;

  for (let offset = 0; offset < totalSize; offset += CHUNK_SIZE) {
    const chunk = file.slice(offset, Math.min(offset + CHUNK_SIZE, totalSize));
    const buf = await chunk.arrayBuffer();
    const hash = await sha256Hex(buf);
    const result = await uploadChunk(hash, buf);
    if (!result.ok) {
      return { ok: false, status: result.status, data: result.data };
    }
    chunkHashes.push(hash);
    bytesDone += buf.byteLength;
    onProgress?.(bytesDone, totalSize);
  }

  return commitFile({ path, logicalSize: totalSize, chunkHashes });
}

/* Downloads versionId's content as a Blob, chunk by chunk, reporting
 * cumulative byte progress against the caller-supplied totalSize (from
 * the file's own listed size_bytes - the chunk list alone doesn't carry
 * a total ahead of time). */
export async function downloadFile(
  versionId: number,
  totalSize: number,
  onProgress?: ProgressCb,
): Promise<Blob> {
  const chunksResult = await getVersionChunks(versionId);
  if (!chunksResult.ok) {
    throw new Error(`could not fetch version chunk list: ${chunksResult.data.status}`);
  }
  if (chunksResult.data.vault_id !== 0) {
    throw new Error("vault-encrypted downloads are not yet supported (TASK-141)");
  }

  const parts: ArrayBuffer[] = [];
  let bytesDone = 0;
  for (const hash of chunksResult.data.chunk_hashes) {
    const buf = await downloadChunk(hash);
    parts.push(buf);
    bytesDone += buf.byteLength;
    onProgress?.(bytesDone, totalSize);
  }
  return new Blob(parts);
}

/*
 * Version history (TASK-140, over TASK-133's version endpoints).
 */

export function listVersions(path: string): Promise<ApiResult<VersionEntry[]>> {
  return apiPost("/api/versions/list", { path });
}

export function restoreVersion(
  path: string,
  versionId: number,
): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/versions/restore", { path, version_id: versionId });
}

/*
 * Sharing + public links (TASK-140, over TASK-134's endpoints).
 *
 * Security note carried from TASK-134/140: a link_token is a bearer
 * credential. This module never logs one (no console.log anywhere here)
 * and returns it to the caller exactly once, on creation, matching the
 * gateway/server's own "never re-display" convention - main.ts's UI is
 * responsible for not leaving it visible/copyable longer than necessary.
 */

export function grantShare(
  fileId: number,
  targetUsername: string,
  permission: number,
  expiresAt = 0,
): Promise<ApiResult<{ share_id: number }>> {
  return apiPost("/api/shares/grant", {
    file_id: fileId,
    target_username: targetUsername,
    permission,
    expires_at: expiresAt,
  });
}

export function revokeShare(shareId: number): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/shares/revoke", { share_id: shareId });
}

// mode: 0 = shares I created, 1 = shares granted to me.
export function listShares(mode: 0 | 1): Promise<ApiResult<ShareEntry[]>> {
  return apiPost("/api/shares/list", { mode });
}

export function createLink(
  fileId: number,
  permission: number,
  expiresAt = 0,
  password = "",
): Promise<ApiResult<{ share_id: number; link_token: string }>> {
  return apiPost("/api/links/create", {
    file_id: fileId, permission, expires_at: expiresAt, password,
  });
}

export function revokeLink(shareId: number): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/links/revoke", { share_id: shareId });
}

export function listLinks(fileIdFilter = 0): Promise<ApiResult<LinkEntry[]>> {
  return apiPost("/api/links/list", { file_id_filter: fileIdFilter });
}

/*
 * Vault registry (TASK-141, over TASK-135's endpoints). All key material
 * here is opaque hex, exactly like the gateway's own contract — nothing
 * in this module ever sees a passphrase; that only ever exists in
 * vault-crypto.ts's deriveKek call and the DOM input it's read from.
 */

export interface VaultEntry {
  vault_id: number;
  folder_file_id: number;
  created_at: number;
}

export interface VaultKeyFetchResponse {
  wrapped_vk: string;
  kdf_salt: string;
  kdf_params: string;
  folder_file_id: number;
}

export function vaultCreate(
  folderFileId: number,
  wrappedVkHex: string,
  kdfSaltHex: string,
  kdfParamsHex: string,
): Promise<ApiResult<{ vault_id: number }>> {
  return apiPost("/api/vault/create", {
    folder_file_id: folderFileId,
    wrapped_vk: wrappedVkHex,
    kdf_salt: kdfSaltHex,
    kdf_params: kdfParamsHex,
  });
}

export function vaultKeyFetch(vaultId: number): Promise<ApiResult<VaultKeyFetchResponse>> {
  return apiPost("/api/vault/key_fetch", { vault_id: vaultId });
}

export function vaultList(): Promise<ApiResult<VaultEntry[]>> {
  return apiPost("/api/vault/list", {});
}

/*
 * Vault-encrypted upload/download (TASK-141): same chunk-transfer loop as
 * uploadFile/downloadFile above, but every chunk is encrypted/decrypted
 * client-side via vault-crypto.ts before it ever reaches uploadChunk/
 * downloadChunk - the gateway only ever sees ciphertext and the opaque
 * wrapped_dek blob, never plaintext or any key.
 *
 * Chunk size differs from the plaintext path: VW_VAULT_PLAINTEXT_CHUNK_BYTES
 * (CHUNK_SIZE - 16) so that ciphertext+tag lands exactly on CHUNK_SIZE,
 * matching vw_vault.c's own vault_reader_next sizing exactly - a mismatch
 * here would silently produce a different chunk count than the native
 * client would for the same file, which is still byte-correct after
 * reassembly but worth keeping identical to avoid any doubt.
 */
const VAULT_PLAINTEXT_CHUNK_SIZE = CHUNK_SIZE - 16;

async function sha256HexOfBuffer(buf: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return bufToHex(digest);
}

export async function uploadFileEncrypted(
  path: string,
  file: File,
  vaultId: number,
  vk: Uint8Array,
  onProgress?: ProgressCb,
): Promise<ApiResult<CommitResponse>> {
  const { randomDek, encryptChunk, wrapKey, bytesToHex: vaultBytesToHex } = await import(
    "./vault-crypto.js"
  );

  const totalSize = file.size;
  const dek = randomDek();
  const chunkHashes: string[] = [];
  let bytesDone = 0;
  let chunkIndex = 0;
  let offset = 0;

  do {
    const end = Math.min(offset + VAULT_PLAINTEXT_CHUNK_SIZE, totalSize);
    const chunk = file.slice(offset, end);
    const plaintextBuf = await chunk.arrayBuffer();
    const ciphertextBuf = await encryptChunk(dek, chunkIndex, plaintextBuf);
    const hash = await sha256HexOfBuffer(ciphertextBuf);

    const result = await uploadChunk(hash, ciphertextBuf);
    if (!result.ok) {
      return { ok: false, status: result.status, data: result.data };
    }

    chunkHashes.push(hash);
    bytesDone += plaintextBuf.byteLength;
    chunkIndex++;
    offset = end;
    onProgress?.(bytesDone, totalSize);
  } while (offset < totalSize);

  const wrappedDek = await wrapKey(vk, dek);
  // The per-file DEK is only needed up to this point (every chunk is
  // already encrypted, and it's now wrapped for storage) - zero it here
  // rather than leaving it for GC, matching the same sensitivity class as
  // kek/vk elsewhere in this codebase (main.ts). Found unzeroed during
  // TASK-141's CQR.08 review.
  dek.fill(0);
  return commitFile({
    path,
    logicalSize: totalSize,
    chunkHashes,
    vaultId,
    wrappedDekHex: vaultBytesToHex(wrappedDek),
  });
}

export async function downloadFileEncrypted(
  versionId: number,
  totalSize: number,
  vk: Uint8Array,
  onProgress?: ProgressCb,
): Promise<Blob> {
  const { unwrapKey, decryptChunk, hexToBytes: vaultHexToBytes } = await import(
    "./vault-crypto.js"
  );

  const chunksResult = await getVersionChunks(versionId);
  if (!chunksResult.ok) {
    throw new Error(`could not fetch version chunk list: ${chunksResult.data.status}`);
  }
  if (chunksResult.data.vault_id === 0 || !chunksResult.data.wrapped_dek) {
    throw new Error("this version is not vault-encrypted");
  }

  const wrappedDek = vaultHexToBytes(chunksResult.data.wrapped_dek);
  const dek = await unwrapKey(vk, wrappedDek);

  const parts: ArrayBuffer[] = [];
  let bytesDone = 0;
  let chunkIndex = 0;
  for (const hash of chunksResult.data.chunk_hashes) {
    const ciphertextBuf = await downloadChunk(hash);
    const plaintextBuf = await decryptChunk(dek, chunkIndex, ciphertextBuf);
    parts.push(plaintextBuf);
    bytesDone += plaintextBuf.byteLength;
    chunkIndex++;
    onProgress?.(bytesDone, totalSize);
  }
  // Same DEK-zeroing discipline as uploadFileEncrypted above - every chunk
  // is already decrypted at this point, so the DEK is no longer needed.
  dek.fill(0);
  return new Blob(parts);
}
