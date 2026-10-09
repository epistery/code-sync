import path from 'path';
import { pathToFileURL } from 'url';

// The compiled server is CommonJS; the wire modules under client/ are pure ESM
// so the browser can import the same bytes. tsc rewrites `import()` in a
// CommonJS build to `require()`, which loads an ES module only on Node 20.19 /
// 22.12 and later. A real dynamic import, reached through Function so tsc leaves
// it alone, works on every Node that has ESM at all — so the server never
// depends on the runtime version for its own wire.
const dynamicImport = new Function('u', 'return import(u)') as (u: string) => Promise<any>;

/** Load one of core's client/ wire modules from the compiled server. */
export function loadClientModule(name: string): Promise<any> {
  return dynamicImport(pathToFileURL(path.join(__dirname, '..', '..', 'client', name)).href);
}
