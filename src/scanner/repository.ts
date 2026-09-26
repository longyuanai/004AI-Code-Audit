import { existsSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

// Path basis shared with the Python stack (contracts/fingerprint.json,
// spec.path). Paths are reported relative to the repository containing the
// working directory, because git diffs, SARIF %SRCROOT% and GitHub review
// comments all speak repository-relative paths; cwd-relative paths made
// --diff drop every finding and SARIF point at the wrong file whenever the CLI
// ran from a subdirectory.

/**
 * The nearest ancestor of `base` holding a `.git` entry (a directory, or a
 * file for worktrees and submodules), or `base` itself outside a repository.
 */
export function findRepositoryRoot(base: string): string {
  const start = resolve(base);
  for (let dir = start; ; dir = dirname(dir)) {
    if (existsSync(join(dir, '.git'))) return dir;
    if (dirname(dir) === dir) return start;
  }
}

export interface ReportedPath {
  /** Repository-relative, forward slashes: what findings and fingerprints use. */
  path: string;
  /** The pre-repository-root form (cwd-relative), kept only to match old baselines. */
  legacyPath: string;
}

export function createPathResolver(base: string = process.cwd()): (file: string) => ReportedPath {
  const root = findRepositoryRoot(base);
  const cwd = resolve(base);
  return file => ({
    path: relative(root, resolve(file)).replace(/\\/g, '/'),
    legacyPath: relative(cwd, resolve(file)).replace(/\\/g, '/'),
  });
}
