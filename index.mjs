/**
 * @epistery/code-sync
 *
 * The one place the "advance a git checkout to a branch, then act" logic lives,
 * so services stop each rolling their own (harness/sync.mjs, epistery-host's
 * PluginManager/AgentManager).
 *
 * The shared CORE is `syncCheckout()`: fetch, no-op when already current, then
 * advance and (only when deps changed) install. Everything that legitimately
 * differs between callers is a parameter:
 *   - advance strategy: 'ff-only' (never clobbers, the harness's choice) vs 'reset-hard'
 *   - install policy: 'if-changed' (default) | 'always' | 'never', + which installer
 *   - what to do after an advance: the caller's onAdvance (restart, hot-reload, …)
 *
 * `poll()` is the first TRIGGER, for a service that keeps its OWN code current
 * under a supervisor: check origin/<branch> on an interval and, when it advanced,
 * hand off to onAdvance (console/relay pass `() => process.exit(0)` and let
 * systemd Restart=always respawn on the new code). Signed-webhook and admin-route
 * triggers (the harness / plugin-manager shapes) can layer on later over the same
 * core; they're intentionally not here yet (they'd drag in express + an auth model).
 *
 * `attach()` is how a host turns it on: settings come from the ONE config system,
 * epistery `Config` (a `[code-sync]` section in the host's own `~/.epistery`
 * config), never env vars — so code-sync's config sits beside the host it runs for.
 * No `[code-sync]` section (or `enabled=false`) = it does nothing.
 *
 * No credential/token handling: a checkout that self-updates fetches with its own
 * remote (deploy key / https). The managed-clone token injection AgentManager does
 * is that caller's concern, not this core's — add it as a param if/when it migrates.
 */
import { spawn } from 'child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { Config } from 'epistery';

// Fail fast instead of hanging on an auth prompt when a remote needs credentials.
const HOSTILE_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never' };

function run(cmd, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, env: HOSTILE_ENV, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout: out.trim(), stderr: err.trim() }));
  });
}

async function git(args, cwd) {
  const r = await run('git', args, cwd);
  if (r.code !== 0) throw new Error(`git ${args.join(' ')} failed (exit ${r.code}): ${r.stderr || r.stdout}`);
  return r.stdout;
}

// `git diff --quiet` exits non-zero exactly when the listed paths changed between
// the two commits — so we install only when package.json / lockfile actually moved.
async function depsChanged(dir, before, after) {
  const r = await run('git', ['diff', '--quiet', before, after, '--', 'package.json', 'package-lock.json'], dir);
  return r.code !== 0;
}

// --- deps-vs-lock reconciliation (used by reconcile/bootstrap) ---------------
// `depsChanged` above is keyed to a GIT ADVANCE — it only knows deps moved when
// HEAD moved this run. That misses the crash-loop case: a box already sitting on
// new code with stale `node_modules` (a push landed while it was down, or an
// earlier advance's install failed). These helpers compare what is INSTALLED to
// the ON-DISK lock, so reconcile can heal that box on a restart even though git
// did not move. The marker lives inside node_modules (npm ci wipes it, so it is
// rewritten only after a successful install) and holds the hash of the lock it
// was installed from.
const INSTALLED_MARKER = ['node_modules', '.code-sync-installed'];

function lockHash(dir) {
  try { return createHash('sha256').update(readFileSync(join(dir, 'package-lock.json'))).digest('hex'); }
  catch { return null; }   // no lockfile → nothing to reconcile against
}

function installedMatchesLock(dir) {
  const want = lockHash(dir);
  if (want === null) return true;                       // no lock: nothing to match
  if (!existsSync(join(dir, 'node_modules'))) return false;
  try { return readFileSync(join(dir, ...INSTALLED_MARKER), 'utf8').trim() === want; }
  catch { return false; }                               // no/unreadable marker → not reconciled yet
}

function markInstalled(dir) {
  const want = lockHash(dir);
  if (want === null) return;
  try {
    mkdirSync(join(dir, 'node_modules'), { recursive: true });   // a zero-dep `npm ci` leaves no node_modules
    writeFileSync(join(dir, ...INSTALLED_MARKER), want);
  } catch { /* best effort — a missed marker only costs one extra ci next boot */ }
}

/**
 * Advance one checkout to origin/<branch>. Pure of any restart/reload — the
 * caller decides what to do with the result.
 *
 * @param {object} opts
 * @param {string} opts.dir                 checkout root (contains .git)
 * @param {string} [opts.branch='main']     branch to track
 * @param {'ff-only'|'reset-hard'} [opts.advance='ff-only']
 * @param {'if-changed'|'always'|'never'} [opts.install='if-changed']
 * @param {string[]} [opts.installer=['ci','--no-audit','--no-fund']]  npm args
 * @returns {Promise<{advanced:boolean, before:string, after:string, installed:boolean}>}
 */
export async function syncCheckout({ dir, branch = 'main', advance = 'ff-only', install = 'if-changed', installer } = {}) {
  if (!dir) throw new Error('code-sync: dir is required');
  await git(['fetch', 'origin', branch], dir);
  const before = await git(['rev-parse', 'HEAD'], dir);
  const target = await git(['rev-parse', `origin/${branch}`], dir);
  if (before === target) return { advanced: false, before, after: before, installed: false };

  if (advance === 'ff-only') await git(['merge', '--ff-only', `origin/${branch}`], dir);
  else if (advance === 'reset-hard') await git(['reset', '--hard', `origin/${branch}`], dir);
  else throw new Error(`code-sync: unknown advance strategy '${advance}'`);

  const after = await git(['rev-parse', 'HEAD'], dir);

  const wantInstall = install === 'always' ? true
    : install === 'never' ? false
    : await depsChanged(dir, before, after);   // 'if-changed'
  if (wantInstall) {
    const args = installer || ['ci', '--no-audit', '--no-fund'];
    const r = await run('npm', args, dir);
    if (r.code !== 0) throw new Error(`npm ${args.join(' ')} failed (exit ${r.code}): ${r.stderr || r.stdout}`);
    markInstalled(dir);   // record the lock we installed from, so bootstrap's reconcile no-ops next boot
  }
  return { advanced: true, before, after, installed: wantInstall };
}

/**
 * Poll origin/<branch> on an interval; on an advance, call onAdvance. Ticks never
 * overlap, and the timer is unref'd so polling alone won't hold the process open.
 *
 * @param {object} opts  — dir/branch/advance/install/installer as syncCheckout, plus:
 * @param {number} [opts.intervalMs=60000]
 * @param {(res)=>any} [opts.onAdvance]     e.g. () => process.exit(0) under a supervisor
 * @param {(err)=>any} [opts.onError]
 * @param {{log?:Function,warn?:Function}} [opts.logger=console]
 * @returns {{stop:()=>void, check:()=>Promise<void>}}
 */
export function poll({ dir, branch = 'main', intervalMs = 60_000, advance = 'ff-only', install = 'if-changed', installer, onAdvance, onError, logger = console } = {}) {
  if (!dir) throw new Error('code-sync: dir is required');
  let running = false;
  let stopped = false;

  async function check() {
    if (running || stopped) return;
    running = true;
    try {
      const res = await syncCheckout({ dir, branch, advance, install, installer });
      if (res.advanced) {
        logger?.log?.(`[code-sync] ${dir} advanced ${res.before.slice(0, 7)}→${res.after.slice(0, 7)}${res.installed ? ' (deps installed)' : ''}`);
        if (onAdvance) await onAdvance(res);
      }
    } catch (e) {
      if (onError) onError(e); else logger?.warn?.(`[code-sync] ${dir}: ${e.message}`);
    } finally {
      running = false;
    }
  }

  const timer = setInterval(check, intervalMs);
  timer.unref?.();

  return {
    stop() { stopped = true; clearInterval(timer); },
    check,   // trigger an immediate check (a future webhook/admin trigger reuses this)
  };
}

const OFF = new Set(['false', 'no', '0', 'off']);

/**
 * Turn code-sync on from the host's epistery Config — the ONE config system, no
 * env vars. Reads a `[code-sync]` section from the root config (`~/.epistery`,
 * beside the host's own settings) and, if present and not disabled, polls
 * origin/<branch>. Absent section (or `enabled=false`) → returns null, does
 * nothing. Never throws into the host: a config-read failure is logged and
 * treated as "not configured".
 *
 * `[code-sync]` keys (all optional): enabled (default on when the section exists),
 * branch (main), interval (seconds, 60), advance (ff-only|reset-hard),
 * install (if-changed|always|never).
 *
 * @param {object} opts
 * @param {string} opts.dir                 checkout root (contains .git)
 * @param {string} [opts.section='code-sync']
 * @param {(res)=>any} [opts.onAdvance]     e.g. () => process.exit(0) under a supervisor
 * @param {{log?:Function,warn?:Function}} [opts.logger=console]
 * @returns {Promise<{stop:()=>void,check:()=>Promise<void>}|null>}
 */
export async function attach({ dir, section = 'code-sync', onAdvance, logger = console } = {}) {
  if (!dir) throw new Error('code-sync: dir is required');
  let cfg;
  try {
    cfg = new Config();
    await cfg.setPath('/');            // root ~/.epistery/config.ini (loads into cfg.data)
  } catch (e) {
    logger?.warn?.(`[code-sync] could not read epistery Config — not tracking: ${e.message}`);
    return null;
  }
  const sec = cfg.data?.[section];
  if (!sec) { logger?.log?.(`[code-sync] no [${section}] in epistery Config — not tracking`); return null; }
  if (OFF.has(String(sec.enabled ?? '').toLowerCase())) {
    logger?.log?.(`[code-sync] [${section}] enabled=false — not tracking`);
    return null;
  }
  const branch = sec.branch || 'main';
  const intervalMs = sec.interval ? Math.max(5, parseInt(sec.interval, 10)) * 1000 : 60_000;
  const advance = sec.advance || 'ff-only';
  const install = sec.install || 'if-changed';
  logger?.log?.(`[code-sync] tracking origin/${branch} (poll ${intervalMs / 1000}s) from [${section}] config`);
  return poll({ dir, branch, intervalMs, advance, install, onAdvance, logger });
}

/**
 * Make a checkout fit to boot, then leave it: advance to origin/<branch> (like
 * syncCheckout) AND guarantee `node_modules` matches the ON-DISK lock — the second
 * part independent of whether git moved this run. syncCheckout installs only on a
 * git advance, so it cannot heal a box already on new code with stale deps; this
 * does, by comparing installed-vs-lock rather than before-vs-after.
 *
 * Throws (does not swallow) if the advance or install fails — the caller
 * (bootstrap) turns that into a clean non-start so the app never loads half-synced.
 *
 * @returns {Promise<{advanced:boolean, before:string, after:string, installed:boolean}>}
 */
export async function reconcile({ dir, branch = 'main', advance = 'ff-only', installer } = {}) {
  if (!dir) throw new Error('code-sync: dir is required');
  // Advance the code but do NOT let syncCheckout decide the install — we own it,
  // keyed to installed-vs-lock so a HEAD that didn't move is still reconciled.
  const res = await syncCheckout({ dir, branch, advance, install: 'never', installer });
  let installed = false;
  if (!installedMatchesLock(dir)) {
    const args = installer || ['ci', '--no-audit', '--no-fund'];
    const r = await run('npm', args, dir);
    if (r.code !== 0) throw new Error(`npm ${args.join(' ')} failed (exit ${r.code}): ${r.stderr || r.stdout}`);
    markInstalled(dir);
    installed = true;
  }
  return { ...res, installed };
}

/**
 * Pre-import entrypoint. Make this the service's process entry (see boot.mjs):
 * it reconciles the checkout to a bootable state BEFORE the app's modules load,
 * then imports the app. Because the reconcile runs before any app import, a
 * module-link failure (a pushed import whose dependency isn't installed yet) can
 * no longer pre-empt it — systemd's next restart heals the box instead of
 * crash-looping. This is the piece `attach()` structurally cannot be: attach runs
 * inside the app, after its imports, so it never gets to run on a boot that fails
 * at link.
 *
 * Config-gated exactly like attach(): no `[code-sync]` section (or enabled=false)
 * means dev / un-managed — the reconcile is SKIPPED (so it never `npm ci`s over a
 * developer's linked node_modules) and the app is imported directly, identical to
 * `node <entry>`.
 *
 * @param {object} opts
 * @param {string} opts.dir     checkout root (contains .git); boot.mjs passes process.cwd()
 * @param {string} opts.entry   the app module to import once reconciled (a file URL or specifier)
 * @param {string} [opts.section='code-sync']
 */
export async function bootstrap({ dir, entry, section = 'code-sync', logger = console } = {}) {
  if (!dir) throw new Error('code-sync: dir is required');
  if (!entry) throw new Error('code-sync: entry is required');
  let sec = null;
  try {
    const cfg = new Config();
    await cfg.setPath('/');
    sec = cfg.data?.[section] || null;
  } catch (e) {
    logger?.warn?.(`[code-sync] bootstrap: could not read Config — starting without reconcile: ${e.message}`);
  }
  const enabled = sec && !OFF.has(String(sec.enabled ?? '').toLowerCase());
  if (enabled) {
    try {
      const res = await reconcile({ dir, branch: sec.branch || 'main', advance: sec.advance || 'ff-only' });
      logger?.log?.(`[code-sync] bootstrap reconciled ${res.before.slice(0, 7)}→${res.after.slice(0, 7)}` +
        `${res.installed ? ' (deps installed)' : ' (deps current)'}`);
    } catch (e) {
      logger?.error?.(`[code-sync] bootstrap reconcile failed — refusing to start on mismatched deps: ${e.message}`);
      process.exit(1);   // systemd Restart=always retries; never launch the app half-synced
    }
  } else {
    logger?.log?.('[code-sync] bootstrap: no [code-sync] config — starting directly (dev / un-managed)');
  }
  await import(entry);
}
