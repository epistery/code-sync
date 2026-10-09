import fs from 'fs';
import fsp from 'fs/promises';
import { join } from 'path';

/**
 * Filesystem permissions for the epistery config tree.
 *
 * ~/.epistery holds wallet mnemonics and private keys in cleartext. Even once
 * keys move into device hardware there will always be a cleartext fallback, so
 * the floor is: secrets are owner-only.
 *
 *   files: 0600   dirs: 0700
 *
 * Two enforcement points:
 *   - every write goes through {@link secureFile} / {@link secureDir}, which
 *     also repairs a pre-existing file that was created too open;
 *   - {@link auditTree} / {@link secureTree} back `epistery permissions
 *     [--fix]` for everything already on disk.
 *
 * chmod is a no-op on Windows, where ACLs (not mode bits) govern access; the
 * helpers skip it there rather than pretend.
 */

export const SECRET_FILE_MODE = 0o600;
export const SECRET_DIR_MODE = 0o700;

/** Permission bits granted to group or other — anything here is too open. */
export const TOO_OPEN_MASK = 0o077;

const canChmod = process.platform !== 'win32';

/** True when the mode grants any group/other access. */
export function isTooOpen(mode: number): boolean {
  return (mode & TOO_OPEN_MASK) !== 0;
}

/** Render a mode as the octal string humans read in `ls -l` output (e.g. "664"). */
export function formatMode(mode: number): string {
  return (mode & 0o777).toString(8).padStart(3, '0');
}

/**
 * Tighten one path to `mode` if it currently grants group/other access.
 * Returns the previous mode when it changed anything, else null. Never throws:
 * a path we don't own is reported by the audit rather than aborting a save.
 */
export async function secureTo(path: string, mode: number): Promise<number | null> {
  if (!canChmod) return null;
  try {
    const stats = await fsp.stat(path);
    if (!isTooOpen(stats.mode)) return null;
    await fsp.chmod(path, mode);
    return stats.mode & 0o777;
  } catch {
    return null;
  }
}

/** Tighten a config file to 0600. */
export function secureFile(path: string): Promise<number | null> {
  return secureTo(path, SECRET_FILE_MODE);
}

/** Tighten a config directory to 0700. */
export function secureDir(path: string): Promise<number | null> {
  return secureTo(path, SECRET_DIR_MODE);
}

/** Synchronous variant, for the one bootstrap write that cannot await. */
export function secureToSync(path: string, mode: number): number | null {
  if (!canChmod) return null;
  try {
    const stats = fs.statSync(path);
    if (!isTooOpen(stats.mode)) return null;
    fs.chmodSync(path, mode);
    return stats.mode & 0o777;
  } catch {
    return null;
  }
}

export interface PermissionEntry {
  path: string;
  type: 'file' | 'dir';
  mode: number;         // current mode (0o777 masked)
  expected: number;     // what it should be
}

/**
 * Walk a config tree and report every file/directory that grants group or
 * other access. Symlinks are reported but not followed — a symlink out of the
 * tree is not ours to chmod.
 */
export async function auditTree(root: string): Promise<PermissionEntry[]> {
  const findings: PermissionEntry[] = [];
  if (!canChmod) return findings;

  const visit = async (path: string): Promise<void> => {
    let stats: fs.Stats;
    try {
      stats = await fsp.lstat(path);
    } catch {
      return;
    }
    if (stats.isSymbolicLink()) return;

    const isDir = stats.isDirectory();
    if (isTooOpen(stats.mode)) {
      findings.push({
        path,
        type: isDir ? 'dir' : 'file',
        mode: stats.mode & 0o777,
        expected: isDir ? SECRET_DIR_MODE : SECRET_FILE_MODE,
      });
    }
    if (!isDir) return;

    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(path, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      await visit(join(path, entry.name));
    }
  };

  await visit(root);
  return findings;
}

/**
 * Tighten everything `auditTree` flags. Returns the entries that were fixed
 * (with their previous mode) and the ones that could not be — a path owned by
 * another user, say — so the caller can report both.
 */
export async function secureTree(root: string): Promise<{ fixed: PermissionEntry[]; failed: PermissionEntry[] }> {
  const fixed: PermissionEntry[] = [];
  const failed: PermissionEntry[] = [];

  // Deepest first: tightening a directory to 0700 doesn't block the owner, but
  // fixing children before parents keeps the walk honest if it is interrupted.
  const findings = (await auditTree(root)).sort((a, b) => b.path.length - a.path.length);

  for (const entry of findings) {
    try {
      await fsp.chmod(entry.path, entry.expected);
      fixed.push(entry);
    } catch {
      failed.push(entry);
    }
  }
  return { fixed, failed };
}

/**
 * Warn — once per path per process — that a config file holding key material
 * is readable by other users. Written to stderr so stdout stays clean for the
 * MCP bridge and for `curl` output.
 */
const warned = new Set<string>();

export function warnIfTooOpen(path: string): void {
  if (!canChmod || warned.has(path)) return;
  let stats: fs.Stats;
  try {
    stats = fs.statSync(path);
  } catch {
    return;
  }
  if (!isTooOpen(stats.mode)) return;

  warned.add(path);
  process.stderr.write(
    `warning: ${path} holds key material but is mode ${formatMode(stats.mode)} ` +
    `(readable by other users on this machine).\n` +
    `         Fix with: epistery permissions --fix\n`,
  );
}

/** True when a parsed config carries cleartext key material. */
export function holdsSecrets(data: any): boolean {
  return !!(
    data?.wallet?.mnemonic ||
    data?.wallet?.privateKey ||
    data?.authority?.machineMnemonic ||
    data?.authority?.machineKey
  );
}
