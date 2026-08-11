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
 */

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
    headers: { "Content-Type": "application/json" },
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

export function login(username: string, password: string): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/login", { username, password });
}

export function loginWithOtp(
  username: string,
  password: string,
  otp: string,
): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/login", { username, password, otp });
}

export function logout(): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/logout", {});
}

export function listFiles(path: string, recursive = false): Promise<ApiResult<FileEntry[]>> {
  return apiPost("/api/files/list", { path, recursive });
}

export function mkdir(name: string, parentDirId = 0): Promise<ApiResult<{ dir_id: number }>> {
  return apiPost("/api/files/mkdir", { name, parent_dir_id: parentDirId });
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
    headers: { "X-Vw-Chunk-Hash": hash },
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
    headers: { "Content-Type": "application/json" },
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
}): Promise<ApiResult<CommitResponse>> {
  const body: Record<string, unknown> = {
    logical_size: opts.logicalSize,
    chunk_hashes: opts.chunkHashes,
  };
  if (opts.path) body.path = opts.path;
  if (opts.fileId !== undefined) body.file_id = opts.fileId;
  if (opts.leafName) body.leaf_name = opts.leafName;
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
): Promise<ApiResult<{ share_id: number; link_token: string }>> {
  return apiPost("/api/links/create", { file_id: fileId, permission, expires_at: expiresAt });
}

export function revokeLink(shareId: number): Promise<ApiResult<StatusResponse>> {
  return apiPost("/api/links/revoke", { share_id: shareId });
}

export function listLinks(fileIdFilter = 0): Promise<ApiResult<LinkEntry[]>> {
  return apiPost("/api/links/list", { file_id_filter: fileIdFilter });
}
