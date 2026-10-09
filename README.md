# @epistery/code-sync

The one place the "advance a git checkout to a branch, then act" logic lives, so
epistery services stop each rolling their own. Its only dependency is core
`epistery` (for `Config`); it does **not** depend on `@metric-im/administrate`, and
it is **not** part of core `epistery` itself (that's tight public middleware — no
ops code there).

Configuration comes from the **one** config system — epistery `Config`, a
`[code-sync]` section in the host's own `~/.epistery` config — **never** env vars.

## `attach()` — the config-driven on-switch (what a host uses)

```js
import { attach } from '@epistery/code-sync';

await attach({
  dir: __dirname,                       // this service's checkout root (contains .git)
  onAdvance: () => process.exit(0),      // systemd Restart=always respawns on new code
});
```

`attach` reads the `[code-sync]` section from root config (`new Config()` →
`setPath('/')`). If the section is absent or `enabled=false`, it returns `null` and
does nothing — so an un-configured box (and dev) is untouched. Otherwise it polls
`origin/<branch>` and, on an advance, calls `onAdvance`. Never throws into the host:
a config-read failure is logged and treated as "not configured".

A host wires it once (console/relay do this after the server is listening) behind a
guarded dynamic import, so a box that doesn't have the package installed yet still
boots:

```js
import('@epistery/code-sync').then(({ attach }) => attach({
  dir: __dirname,
  onAdvance() {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5_000).unref();   // hard stop if close hangs
  },
})).catch((e) => console.warn('[code-sync] unavailable:', e.message));
```

## `bootstrap()` — pre-import reconcile (the crash-loop guarantee)

`attach()` runs **inside** the app, after its top-level imports. That is fine for a
*live* advance (the old process installs, then exits, and the new deps are in place
on respawn — see Restart model). But it cannot help a boot that **fails at module
link**: if a box ever lands on new code with stale/missing deps (a push arrived while
it was down, an earlier advance's `npm ci` failed, a manual pull), the next start
throws at the bad `import` *before* `attach()` ever runs. The in-process self-healer
is dead on arrival, and the box crash-loops with no way to pull its own fix.

`bootstrap()` closes that hole by reconciling **before the app's imports** and then
importing the app. Make it the process entrypoint via `boot.mjs`:

```ini
ExecStart=/usr/bin/node node_modules/@epistery/code-sync/boot.mjs index.mjs
```

```js
// what boot.mjs does — the host writes no logic, it just points its entry here
import { bootstrap } from '@epistery/code-sync';
await bootstrap({ dir: process.cwd(), entry: './index.mjs' });
```

`bootstrap` is config-gated exactly like `attach` — **no `[code-sync]` section (or
`enabled=false`) and it imports the entry directly, identical to `node index.mjs`**,
so dev and un-managed boxes are untouched and a developer's linked `node_modules` is
never `npm ci`'d over. When the section is present it:

1. advances the checkout to `origin/<branch>` (ff-only), then
2. ensures `node_modules` matches the **on-disk `package-lock.json`** — keyed to
   *installed-vs-lock*, not to a git advance, so a box already on new code with stale
   deps is still reconciled (the exact case `syncCheckout`'s `if-changed` misses), then
3. imports the app. If the reconcile fails it logs and **exits non-zero** — systemd
   retries, and the app never loads against mismatched deps.

Run it alongside `attach()` (the live trigger), not instead of it: a live advance
still installs in the old process and exits; every respawn then reconciles before
import, so an advance that failed to install self-heals on the next restart.

## Lower-level primitives

`attach` is built on two pieces you can use directly:

```js
import { syncCheckout, poll } from '@epistery/code-sync';

// advance ONE checkout, no restart — the caller decides what an advance means
const res = await syncCheckout({
  dir,
  branch: 'main',
  advance: 'ff-only',        // 'ff-only' (never clobbers) | 'reset-hard'
  install: 'if-changed',     // 'if-changed' (default) | 'always' | 'never'
  installer: ['ci', '--no-audit', '--no-fund'],  // npm args (optional)
});
// → { advanced, before, after, installed }

// poll on an interval; ticks never overlap, timer is unref'd
const sync = poll({ dir, branch: 'main', intervalMs: 60_000, onAdvance: () => process.exit(0) });
// sync.stop()  — stop polling
// sync.check() — force an immediate check (a future webhook/admin trigger reuses this)
```

`syncCheckout` fetches, **no-ops when already current**, else advances and installs
only when `package.json`/`package-lock.json` changed.

## Restart model

`code-sync` never restarts the process itself. For a service that keeps its **own**
code current, run it under a supervisor (systemd `Restart=always`) and pass
`onAdvance: () => process.exit(0)` (close the server first for a graceful exit). The
install runs in the old process; the restart brings up the new code with the new
deps already in place. Because it exits rather than calling `systemctl`, it needs
**no `sudo`** and no unit-name matching.

For that "new deps already in place" to hold even when the in-process install never
ran (a boot that fails at module link — see `bootstrap()` above), make `boot.mjs` the
entrypoint. `attach()` + `boot.mjs` together are the full guarantee: the live trigger
plus a pre-import reconcile on every respawn.

## Deployment

The host already calls `attach()`; enabling it on a box is config + supervisor:

1. **The checkout is a git clone**, with an `origin` remote tracking the branch and
   working fetch credentials (a deploy key, or an https token) — `code-sync` runs
   `git fetch` with the checkout's own remote, no credential injection of its own.
   It sets `GIT_TERMINAL_PROMPT=0`, so a missing credential fails fast rather than
   hanging.
2. **Run under systemd with `Restart=always`** (sample below).
3. **Enable it** by adding a `[code-sync]` section to the `~/.epistery/config.ini`
   of the user the service runs as (`Config` reads that user's home — so `HOME`/
   `User=` in the unit must point at the right one).
4. **Verify**: push to the tracked branch; within `interval` seconds the log shows
   `[code-sync] … advanced <old>→<new>` and the unit respawns on the new code.

### Sample `[code-sync]` section (`~/.epistery/config.ini`)

```ini
[code-sync]
; enabled: omit or set false to turn off without deleting the section
enabled = true
; branch to track (default main)
branch = main
; poll seconds (default 60; min 5)
interval = 60
; advance: ff-only (default, never clobbers) | reset-hard
advance = ff-only
; install: if-changed (default) | always | never
install = if-changed
```

(Comments are shown on their own lines — the safe style across `ini` versions.
`enabled`/`interval` are read tolerantly, so a native boolean/number or a plain
string both work.)

An absent `[code-sync]` section = disabled. `ff-only` refuses to advance if the
checkout has diverged from the branch (it never discards local commits/edits) — a
production checkout that follows "never edit on the box" has none, so it fast-
forwards cleanly; use `reset-hard` only where you deliberately want the box forced
to the branch.

### Sample systemd unit

```ini
[Unit]
Description=epistery console
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=epistery
Environment=HOME=/home/epistery          # where ~/.epistery/config.ini lives
WorkingDirectory=/opt/console            # the git checkout code-sync advances
ExecStart=/usr/bin/node node_modules/@epistery/code-sync/boot.mjs index.mjs
Restart=always                           # boot.mjs reconciles deps before importing index.mjs
RestartSec=2

[Install]
WantedBy=multi-user.target
```

**Relay is multi-instance behind the NLB**: every instance runs `attach()` and polls
independently, so a push converges all of them — no webhook fan-out needed. Give each
instance the same `[code-sync]` config.

## Not here yet

Signed-webhook (GitHub `X-Hub-Signature-256`) and admin-route triggers — the harness
`sync.mjs` and epistery-host `PluginManager`/`AgentManager` shapes — layer over the
same `syncCheckout` core and can migrate onto this module later. They're omitted for
now to avoid pulling in express and an auth model. Credential/token injection for
private managed clones is likewise a caller concern, added as a parameter if/when
those callers migrate.
