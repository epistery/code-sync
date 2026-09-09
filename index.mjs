/**
 * @epistery/code-sync
 *
 * The one place the "advance a git checkout to a branch, then act" logic lives,
 * so services stop each rolling their own (harness/sync.mjs, epistery-host's
 * PluginManager/AgentManager). It deliberately does NOT depend on
 * @metric-im/administrate (whose Synchronize is the very thing services copied
 * to avoid that dep) and is NOT part of core `epistery` (tight public
 * middleware — no ops code there).
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
