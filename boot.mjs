#!/usr/bin/env node
/**
 * code-sync bootstrap launcher — the service's process entrypoint.
 *
 * Make systemd run THIS instead of `node index.mjs`:
 *
 *   ExecStart=/usr/bin/node node_modules/@epistery/code-sync/boot.mjs index.mjs
 *
 * It reconciles the checkout (advance to origin/<branch> + make node_modules match
 * the on-disk lock) BEFORE importing the app, so a dependency/import mismatch is
 * healed on restart instead of crash-looping. All the logic lives in code-sync's
 * bootstrap(); the host just points its entrypoint here and passes its real entry.
 *
 * The checkout root is the process CWD (systemd WorkingDirectory); the entry
 * argument is resolved against it. With no `[code-sync]` config (dev / un-managed),
 * bootstrap skips the reconcile and imports the entry directly — identical to
 * `node <entry>`.
 */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { bootstrap } from './index.mjs';

const entryArg = process.argv[2];
if (!entryArg) {
  console.error('usage: node node_modules/@epistery/code-sync/boot.mjs <entry.mjs>  (run from the checkout root)');
  process.exit(2);
}

const dir = process.cwd();
const entry = pathToFileURL(resolve(dir, entryArg)).href;
await bootstrap({ dir, entry });
