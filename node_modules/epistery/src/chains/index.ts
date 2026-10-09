/**
 * Chains module barrel.
 *
 * Exports the public API and pulls in the built-in chain subclasses for
 * their side-effect (each subclass calls registerChain() at module load).
 *
 * Adding a new built-in chain: drop a `MyChain.ts` next to this file that
 * extends Chain and calls `registerChain(MyChain.chainId, MyChain)` at the
 * bottom, then add one `import './MyChain';` line below. No edits to
 * Chain.ts or registry.ts.
 *
 * Adding a chain from outside this package: write the same kind of file in
 * your own codebase and `import 'your-package/dist/chains/MyChain';` at app
 * startup. The Map in registry.ts is module-scoped, so the registration
 * happens exactly once.
 */

// Public API
export { Chain, ChainConfig, ChainFeeData, ChainPolicy, serverRpcOf, publicRpcOf } from './Chain';
export { chainFor, registerChain, hasRegisteredChain, registeredChainIds, registeredChains, configuredChains, attestationConfig, defaultChainId, findChain, defaultChain, setDefaultChain, providerConfigFor, rootProvider } from './registry';
// registeredChains: internal use + configuredChains(); not re-exported from index.mjs

// Built-in chains — imported for their registerChain() side effect.
// Re-exported so callers that want a concrete subclass (e.g. for instanceof
// checks or to subclass it themselves) can import from the barrel.
export { PolygonChain, AmoyChain } from './PolygonChain';
export { EthereumChain, SepoliaChain } from './EthereumChain';
export { JapanOpenChain } from './JapanOpenChain';
