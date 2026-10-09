import { Chain, ChainConfig, serverRpcOf } from './Chain';
import { Config } from '../utils/Config';

type ChainCtor = (new (config: ChainConfig) => Chain) & { defaults: Partial<ChainConfig> };

/**
 * Registry of chainId → Chain subclass.
 *
 * Adding a chain is a single-file operation: write `MyChain.ts` extending
 * `Chain`, and at the bottom of that file call:
 *
 *     registerChain(MyChain.chainId, MyChain);
 *
 * Then ensure the file is imported once during startup (the built-in
 * `chains/index.ts` does this for the chains shipped with the package; for
 * downstream additions, just `import 'mypackage/chains/MyChain'` from your
 * app entry point).
 *
 * No edits to this file or the barrel are required.
 */
const REGISTRY = new Map<number, ChainCtor>();

/**
 * The registry's ONE Config, root path only. Every read here is of '/', so one
 * instance serves them all; a fresh `new Config()` per call re-authenticated to
 * the authority on every call in remote mode.
 */
let ROOT_CONFIG: Config | null = null;
function rootConfig(): Config {
  if (!ROOT_CONFIG) ROOT_CONFIG = new Config();
  return ROOT_CONFIG;
}

/**
 * The ONE place the root config's provider block is read. A multi-domain root
 * keeps it at `[default.provider]` (epistery-host); a single-domain root at
 * `[provider]` — the same thing, the provider a domain uses when its own
 * config names none. Undefined when the root names neither.
 */
export function rootProvider(rootData: any): ChainConfig | undefined {
  return rootData?.default?.provider ?? rootData?.provider;
}

/**
 * Register a Chain subclass for a given chainId. Overwrites any existing
 * entry — last write wins, so a downstream app can override a built-in if it
 * wants different fee policy.
 */
export function registerChain(chainId: number, ctor: ChainCtor): void {
  REGISTRY.set(Number(chainId), ctor);
}

/**
 * Get a Chain instance for the given provider config. The caller's config
 * is merged ON TOP of the subclass's built-in defaults, so only chainId is
 * strictly required — everything else (name, rpc, currency) comes from the
 * chain class if not explicitly overridden.
 *
 * This means a host installation only needs to set `privateRpc` in
 * `~/.epistery/config.ini` for chains where the public RPC is insufficient;
 * all other details live in the chain class.
 *
 * If no subclass is registered for the chainId, returns a generic Chain —
 * which uses pure EIP-1559 with no floors and the standard estimateGas.
 */
export function chainFor(config: ChainConfig): Chain {
  if (config.chainId == null) {
    throw new Error(`chainFor: provider config missing chainId: ${JSON.stringify(config)}`);
  }
  const Ctor = REGISTRY.get(Number(config.chainId)) || Chain;
  // Subclass defaults fill in anything the caller didn't specify.
  const merged: ChainConfig = { ...(Ctor.defaults as ChainConfig), ...config };
  // If caller provided only `rpc` but chain has a default public RPC,
  // preserve the public one for UI display.
  if (!config.publicRpc && Ctor.defaults.rpc) {
    merged.publicRpc = Ctor.defaults.rpc;
  }
  return new Ctor(merged);
}

/**
 * Return the built-in chain list — one entry per registered chain, using
 * each subclass's defaults. This is the authoritative network list for
 * UI dropdowns. No root config needed.
 */
export function registeredChains(): ChainConfig[] {
  const chains: ChainConfig[] = [];
  for (const [chainId, Ctor] of REGISTRY) {
    chains.push({
      ...(Ctor.defaults as ChainConfig),
      chainId,
    });
  }
  return chains;
}

/**
 * Return the chain list with `privateRpc` overlaid from root config.
 *
 * Looks in `~/.epistery/config.ini` for:
 *   - `[default.rpc.<chainId>] privateRpc = ...`  (per-chain override)
 *   - the root provider block (`rootProvider`), for its own chain
 *
 * Chains without a config override are returned unchanged.
 */
export async function configuredChains(): Promise<ChainConfig[]> {
  const rootData = await rootConfig().read('/');
  const root = rootProvider(rootData);
  return registeredChains().map(chain => {
    const id = String(chain.chainId);
    const privateRpc = rootData?.default?.rpc?.[id]?.privateRpc
      || (root && String(root.chainId) === id ? serverRpcOf(root) : null);
    return privateRpc ? { ...chain, privateRpc } : chain;
  });
}

/**
 * How a chain's ATTESTATION reads are answered — the owned nodes, and how many of
 * them must assert an answer (EpisteryChainReads, Proposal A). Root config (the
 * Authority's, where the process has one):
 *
 *   [chains.polygon]
 *   attest[] = https://node1.example/
 *   attest[] = https://node2.example/
 *   attest[] = https://node3.example/
 *   quorum   = 2        ; k of n, like a multisig — unset: a majority of the nodes
 *
 * The section is named by any selector findChain accepts (alias, name, chainId).
 * Each host sets its own strictness. No node configured is a misconfiguration: it
 * throws — an attestation read never falls through to a public or foreign endpoint.
 */
export async function attestationConfig(chainId: number | string): Promise<{ rpcs: string[]; quorum: number | null }> {
  const rootData = await rootConfig().read('/');
  const sections = rootData?.chains || {};
  const rpcs: string[] = [];
  let quorum: number | null = null;
  for (const [slug, section] of Object.entries<any>(sections)) {
    const chain = await findChain(slug).catch(() => null);
    if (!chain || Number(chain.chainId) !== Number(chainId)) continue;
    const listed = section?.attest;
    for (const url of (Array.isArray(listed) ? listed : listed ? [listed] : [])) {
      if (url && !rpcs.includes(url)) rpcs.push(String(url));
    }
    if (section?.quorum != null && section.quorum !== '') quorum = Number(section.quorum);
  }
  if (!rpcs.length) {
    throw new Error(`No attestation node for chain ${chainId}: set [chains.<name>] attest[] = <owned node> in config — an attestation read is answered by owned nodes or not at all`);
  }
  if (quorum != null && (!Number.isInteger(quorum) || quorum < 1 || quorum > rpcs.length)) {
    throw new Error(`[chains.<name>] quorum = ${quorum} for chain ${chainId} is not between 1 and the ${rpcs.length} attest node(s)`);
  }
  return { rpcs, quorum };
}

/**
 * Return the configured default chainId from root config.
 *
 * Checks `[default] defaultChainId`, then the root provider block's chainId,
 * falling back to Polygon mainnet (137).
 */
export async function defaultChainId(): Promise<string> {
  const rootData = await rootConfig().read('/');
  return String(
    rootData?.default?.defaultChainId
    || rootProvider(rootData)?.chainId
    || '137'
  );
}

/** Visible for tests / debug. Returns true if a chainId has a registered subclass. */
export function hasRegisteredChain(chainId: number): boolean {
  return REGISTRY.has(Number(chainId));
}

/** Visible for tests / debug. Returns the list of registered chainIds. */
export function registeredChainIds(): number[] {
  return Array.from(REGISTRY.keys());
}

/**
 * Resolve a user-supplied chain selector to a chain config.
 *
 * Accepts a chainId (`137`), one of the chain's aliases (`polygon`, `pol`),
 * or its name (`"Polygon Mainnet"`, `polygon-mainnet`) — matching is
 * case-insensitive and ignores spaces, dashes and underscores. A name may be
 * abbreviated as long as exactly one chain matches; an ambiguous
 * abbreviation throws with the candidates.
 *
 * Returns the *configured* chain (privateRpc overlaid from root config), or
 * null when nothing matches, so callers can print the available list.
 */
export async function findChain(selector: string | number): Promise<ChainConfig | null> {
  const chains = await configuredChains();
  const raw = String(selector).trim();
  if (!raw) return null;

  if (/^\d+$/.test(raw)) {
    return chains.find(c => Number(c.chainId) === Number(raw)) || null;
  }

  const norm = (s: string) => s.toLowerCase().replace(/[\s_-]+/g, '');
  const want = norm(raw);

  const alias = chains.filter(c => (c.aliases || []).some(a => norm(a) === want));
  if (alias.length >= 1) return alias[0];

  const exact = chains.filter(c => norm(c.name || '') === want);
  if (exact.length === 1) return exact[0];

  const partial = chains.filter(c => norm(c.name || '').startsWith(want));
  if (partial.length === 1) return partial[0];
  if (partial.length > 1) {
    throw new Error(
      `Chain '${raw}' is ambiguous: ${partial.map(c => `${c.name} (${c.chainId})`).join(', ')}`
    );
  }
  return null;
}

/**
 * Resolve the chain a new wallet should use when the caller didn't name one:
 * root config's `[default] defaultChainId` / the root provider's chainId,
 * else Polygon mainnet. Falls back to the raw root provider block when that
 * chainId has no registered subclass, so a hand-configured chain keeps
 * working.
 */
export async function defaultChain(): Promise<ChainConfig> {
  const id = await defaultChainId();
  const found = await findChain(id);
  if (found) return found;

  const provider = rootProvider(await rootConfig().read('/'));
  if (provider?.chainId) return { ...provider, chainId: Number(provider.chainId) };

  throw new Error(`No chain registered for chainId ${id} and no [default.provider] or [provider] in ~/.epistery/config.ini`);
}

/**
 * Set the chain used by default for new wallets, in root config. Writes both
 * `[default] defaultChainId` and the `[default.provider]` block so consumers
 * that read either one agree. Returns the chain that was set.
 */
export async function setDefaultChain(selector: string | number): Promise<ChainConfig> {
  const chain = await findChain(selector);
  if (!chain) throw new Error(`Unknown chain: ${selector}`);

  const config = rootConfig();
  await config.setPath('/');
  if (!config.data.default) config.data.default = {};
  config.data.default.defaultChainId = String(chain.chainId);
  config.data.default.provider = providerConfigFor(chain);
  await config.save();
  return chain;
}

/**
 * Flatten a chain into the `provider` block shape stored in config.ini
 * (domain configs and root `[default.provider]`). The stored `rpc` is the
 * one the server sends through (serverRpcOf).
 */
export function providerConfigFor(chain: ChainConfig): ChainConfig {
  return {
    chainId: Number(chain.chainId),
    name: chain.name,
    rpc: serverRpcOf(chain),
    nativeCurrencyName: chain.nativeCurrencyName,
    nativeCurrencySymbol: chain.nativeCurrencySymbol,
    nativeCurrencyDecimals: chain.nativeCurrencyDecimals,
  };
}
