# @epistery/code-sync

The one place the "advance a git checkout to a branch, then act" logic lives, so
epistery services stop each rolling their own. No dependency on
`@metric-im/administrate`, and **not** part of core `epistery` (which is tight
public middleware — no ops code there).

## Core

```js
import { syncCheckout } from '@epistery/code-sync';

const res = await syncCheckout({
  dir,                       // checkout root (contains .git)
  branch: 'main',
  advance: 'ff-only',        // 'ff-only' (never clobbers) | 'reset-hard'
  install: 'if-changed',     // 'if-changed' (default) | 'always' | 'never'
  installer: ['ci', '--no-audit', '--no-fund'],  // npm args (optional)
});
// → { advanced, before, after, installed }
```

`syncCheckout` fetches, **no-ops when already current**, else advances and
installs only when `package.json`/`package-lock.json` changed. It performs **no**
restart — the caller decides what an advance means.

## Poll trigger (self-updating service under a supervisor)

```js
import { poll } from '@epistery/code-sync';

const sync = poll({
  dir: appRoot,
  branch: 'main',
  intervalMs: 60_000,
  onAdvance: () => process.exit(0),   // systemd Restart=always respawns on new code
});
// sync.stop()  — stop polling
// sync.check() — force an immediate check (a future webhook/admin trigger reuses this)
```

Ticks never overlap; the interval timer is `unref`'d, so polling alone won't keep
the process alive.

## Restart model

`code-sync` never restarts the process itself. For a service that keeps its **own**
code current, run it under a supervisor (systemd `Restart=always`) and pass
`onAdvance: () => process.exit(0)` (optionally close the server first for a graceful
exit). The install runs in the old process; the restart brings up the new code with
the new deps already in place.

## Not here yet

Signed-webhook (GitHub `X-Hub-Signature-256`) and admin-route triggers — the
harness `sync.mjs` and epistery-host `PluginManager`/`AgentManager` shapes — layer
over the same `syncCheckout` core and can migrate onto this module later. They're
omitted for now to keep this dependency-free (no express, no auth model baked in).
Credential/token injection for private managed clones is likewise a caller concern,
added as a parameter if/when those callers migrate.
