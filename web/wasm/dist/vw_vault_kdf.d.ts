/*
 * Hand-authored declaration for the Emscripten-generated
 * vw_vault_kdf.js (built by ../build.sh, TASK-141) — the glue file
 * itself is plain JS with no type info of its own. Placed here (not
 * checked-in vs. rebuilt: see build.sh's own note on why dist/ is
 * committed like any other prebuilt web asset) so tsc's normal
 * sibling-.d.ts resolution picks it up for the relative import in
 * vault-crypto.ts, without an ambient `declare module` block (which
 * TypeScript rejects for relative specifiers). Scoped to just the
 * surface this project actually calls.
 */

export interface VaultKdfModule {
  _malloc(size: number): number;
  _free(ptr: number): void;
  HEAPU8: Uint8Array;
  ccall(
    ident: string,
    returnType: string,
    argTypes: string[],
    args: unknown[],
  ): unknown;
}

export default function createVaultKdfModule(
  opts?: Record<string, unknown>,
): Promise<VaultKdfModule>;
