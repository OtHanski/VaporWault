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
