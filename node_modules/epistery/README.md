# Epistery

_Epistemology is the study of knowledge. An Epistery, it follows, is a place to share the knowledge of knowledge._

**Epistery is the identity foundation for web applications.** It gives a host one
thing it can trust on every request — a cryptographically proven address — and
binds that address to an on-chain IdentityContract when the user wants a durable
multi-device identity. Everything else (data, ACLs, naming, content) is the host
application's concern, not epistery's.

> **Status — sealed contract, v1.2 (2026-05-27).** This README defines what
> epistery is responsible for, what it is not, and its interface. Code is held to
> this document. The `agent.sol` surface (data wallets, approvals, whitelist /
> lists / roles, name registry, notabot) was **removed in v1.2**; see the wiki
> archives ([[NotABot]], [[Whitelist]], [[DataWallets]], [[Approvals]],
> [[ContractStandards]]) and git tag `epistery-pre-identity-refactor` for the
> retired implementations. The dated **[Known divergences](#known-divergences-audit)**
> section at the end lists where the current code still fails this contract.
> If behavior and this document disagree, that is a bug in the code, not the doc.

---

## Responsibility (what epistery OWNS)

Epistery is the **single owner** of:

1. **Identity** — proving *who* a request is from. The proof is a wallet
   signature, carried either by a short-lived signed session cookie (`_epistery`,
   established via the `/connect` handshake) or a per-request `Bot` signature.
   The result is a trusted **address** on `req.episteryClient`.
2. **Identity binding** — relating a device key (rivet) to an **IdentityContract**,
   verified on-chain (`isAuthorized`). When bound, epistery presents the *contract*
   as the identity.
3. **Key custody (client)** — generating and protecting the user's signing key in
   the browser (non-extractable; see [Key custody](#identity--key-custody)).
4. **Domain/server wallet & config** — the host's own wallet and the path-based
   `~/.epistery` configuration.
5. **FIDO blob storage** — server-side backup of WebAuthn-PRF-wrapped rivet keys
   so they survive iOS ITP IndexedDB eviction.

No consumer may bypass, re-derive, or duplicate any of these. In particular: a
downstream service **never** trusts a client-supplied identity header and
**never** re-implements identity resolution.

---

## What Epistery DOES

- **Authenticates every request** to a trusted address (`req.episteryClient`),
  via signed `_epistery` session cookie or `Bot` signature. A `Bot` signature
  covers the request it authorises — method, URI, audience host and a digest of
  the body, with a timestamp and single-use nonce — so it is a message signature,
  not a bearer token. The bytes are built by `client/bot-auth-message.mjs`, the
  single definition shared by every signer and the verifier.
- **Mints/loads wallets** for the browser (rivet / FIDO / web3) and server
  (per-domain).
- **Binds a device to an IdentityContract** and verifies that binding on-chain.
- **Serves client libraries** at `/lib/*` (`witness.js`, `wallet.js`, `ethers.js`,
  …) and contract artifacts at `/artifacts/*` for consumers.
- **Persists FIDO blobs** (`/fido/blob`) — encrypted, PRF-wrapped rivet keys for
  WebAuthn-backed identities.
- **Backs a CLI** ([`@epistery/cli`](https://github.com/epistery/cli)) for stateless bot-authenticated requests (`curl`), the
  Streamable-HTTP MCP bridge (`mcp`), domain initialization, and basic info.

## What Epistery does NOT do

- **Does not store application data.** Apps own their storage; epistery records
  identity, not your documents.
- **Does not manage contracts.** It *binds keys to existing contracts* and
  *verifies* the binding on-chain — it does not deploy, write to, or own
  application contracts. Contract creation and on-chain ACL/state live in host
  contracts (e.g. `IdentityContractV3.sol`, `DomainContract.sol`).
- **Does not define application- or session-level ACLs.** Authorization is the
  host's job, evaluated against the trusted address epistery provides.
- **Does not run a name registry.** Per-domain naming is a relay service; epistery
  carries no name → address mapping.
- **Does not accept a client's claim of identity.** The only identity is the one
  epistery itself proved (`req.episteryClient`). There is no "I am contract X"
  header. Contract identity claims are verified on-chain at `/connect` and sealed
  into the signed cookie.
- **Does not let downstream code adjudicate auth.** Re-deriving identity or
  re-checking signatures outside epistery is a contract violation.

---

## The trust contract: `req.episteryClient`

The attach middleware sets exactly this on each request (or leaves it `undefined`):

| Field             | Meaning |
|-------------------|---------|
| `signerAddress`   | **The signer.** The rivet whose signature was verified (cookie session or `Bot`). Always non-null. The only thing the client can assert by itself. |
| `contractAddress` | **A verified contract claim.** When the client claimed an IdentityContract at `/connect`, this is that contract, verified on-chain via `isAuthorized(contractAddress, signerAddress)`. `null` when no claim. |
| `identityAddress` | **The canonical identity.** Derived: `contractAddress || signerAddress`. This is what host ACLs evaluate against. Always non-null. |
| `publicKey`       | The signer's public key. |
| `authenticated`   | Whether the session/handshake completed. |
| `authType`        | `"bot"` for `Bot`-signed requests; `"cookie"` for session-cookie. |

The three roles are kept separate on purpose. `signerAddress` is a fact the
client proves; `contractAddress` is a claim the server verifies; `identityAddress`
is the server's derivation. The wire never asks the client to pick which role
its address plays.

**Rule for consumers:** authorize against `identityAddress`. The signer vs.
contract distinction is available but rarely your concern.

```javascript
app.get('/thing', (req, res) => {
  const me = req.episteryClient;            // the ONLY source of identity
  if (!me?.authenticated) return res.status(401).end();
  // authorize against your host's contracts / policy using me.identityAddress
});
```

### The wire (POST `/connect`)

The handshake body carries facts only:

| Field             | Required | Meaning |
|-------------------|----------|---------|
| `signerAddress`   | yes      | The rivet. Must equal the address recovered from `signature` over `message`. |
| `signerPublicKey` | yes      | The signer's public key. |
| `contractAddress` | yes      | An IdentityContract claim, or `null`. When non-null, the server verifies it on-chain via `isAuthorized(contractAddress, signerAddress)`. |
| `challenge`, `message`, `signature` | yes | Proof of signer (see [Identity & key custody](#identity--key-custody)). |
| `walletSource`    | no       | `"rivet"` / `"fido"` / `"web3"` / etc. — informational. |

There is no `clientAddress`, no `identityAddress` on the wire. Either of those
would force the receiver to guess which role the address plays. The server
derives `identityAddress` from the two facts and exposes it on
`req.episteryClient`; the client never tells the server what its identity *is*.

### Tab sessions — two tabs, two rivets

A browser origin can hold several rivets. Which one is active is a property of
the **tab**, not of the device, so two tabs can be two different identities at
once and neither disturbs the other.

| Where | What it holds |
|-------|---------------|
| `sessionStorage["epistery.tab"]` | This tab's id. Per-tab by construction; survives reload, dies with the tab. |
| `sessionStorage["epistery.wallet"]` | The wallet id this tab is being. Outranks the device default. |
| `localStorage["epistery"].defaultWalletId` | The **device** default — what a brand new tab starts as. Last switch wins. |
| `_epistery` cookie | A jar of proven sessions, **one slot per tab**. Still httpOnly; still facts only. |

A request says which slot it means:

- `X-Epistery-Tab: <tab>` — added to every same-origin `fetch` by
  `client/tab.js`'s shim.
- `?_tab=<tab>` — for a WebSocket upgrade, which cannot carry a header.
- Nothing at all — resolves to the jar's **default** slot, the one written by the
  most recent key exchange.

Two rules make the isolation real rather than decorative:

1. A request that names a slot the jar does **not** hold resolves to **no
   session**, never the default. Falling back would hand a tab an identity it
   never proved; instead the tab hand-shakes for itself.
2. The tab header is sent only **after** that tab has performed a key exchange.
   Until then a request carries no tab header and reads the default slot — which
   is exactly the pre-tab behaviour, so an older client, a `curl`, and a page
   that never hand-shakes all keep working unchanged.

`sessionFromJar(req)` is the single resolver; the attach middleware and
`resolveClient()` both call it, so an ordinary request and a WebSocket upgrade
can never disagree about who a tab is.

**Two limits, not papered over.** A document navigation cannot carry a header and
a cookie cannot be scoped to a tab, so the HTML request for a page resolves
against the default slot — tab identity covers the API surface, not the page
load. And "Duplicate tab" copies `sessionStorage`, so the copy starts out
sharing the original's slot until it switches; opening a new tab normally gives a
fresh, independent one.

---

## Identity & key custody

The browser signing key is created and protected by epistery. Custody depends on
wallet type:

| Wallet         | Key custody | Security property |
|----------------|-------------|-------------------|
| **RivetWallet** (default) | secp256k1 private key **encrypted at rest** by a **non-extractable** AES-GCM `CryptoKey` held in IndexedDB (WebCrypto). Only ciphertext + a key id are persisted. **Refuses to create the wallet if WebCrypto is unavailable** — no plaintext fallback. | The signing key cannot be exported — the core "unextractable device key" property. |
| **FidoWallet** | Rivet key wrapped by a WebAuthn PRF secret (Secure Enclave); blob optionally backed up server-side via `/fido/blob` (survives iOS ITP eviction). | Key release gated by platform authenticator. |
| **Web3Wallet** | External plugin (e.g. MetaMask) holds the key. | Custody is the plugin's. |

A device can hold **multiple independent rivets** (Browser/FIDO/Web3 are all
rivets — different ways of presenting a device-locked signing key). This is how
the system enforces one-key-one-identity without a hard cross-context check: the
user mints another isolated rivet rather than pointing one key at two contracts.

**Paper backup rivets.** A rivet can also be derived from a secret the user keeps
**offline** — either a generated 12-word BIP39 phrase or an arbitrary passphrase
(e.g. `peanut butter`, stretched with PBKDF2). Its address is authorized as an
ordinary signer on the IdentityContract, but its key lives only on paper, so it
has **no agency on any device until it is used to recover**. On recovery the
secret re-derives the key and it is **re-homed as a normal RivetWallet**
(non-extractable, encrypted at rest) on the recovering device — no new wallet
type, no secret persisted in the clear. This is the sovereign counterpart to
server-side FIDO blob backup: nothing is escrowed; the human holds the only copy.
A passphrase must be at least 10 characters (letters, numbers, spaces and
punctuation); its strength beyond that is the user's choice. See the paper
helpers under Client API below.

Server/domain wallets live in `~/.epistery/<domain>/config.ini` as **cleartext**
mnemonics — there is no browser-style non-extractable key on the server side, and
even once keys move into device hardware this stays as the fallback. The floor is
filesystem-level: epistery creates every directory in that tree `0700` and every
file `0600`, tightens a file that predates the rule as it writes it, and warns on
stderr when it loads key material from a file other users can read.

```bash
epistery permissions          # audit ~/.epistery (exit 1 if anything is group/other-readable)
epistery permissions --fix    # tighten it
```

`auditTree` / `secureTree` are exported from the package so a host can run the
same check at startup.

### The `/connect` handshake & contract binding

1. The client `Witness` signs a challenge with its rivet and POSTs to `/connect`
   with `signerAddress` (the rivet), `signerPublicKey`, and `contractAddress`
   (the claim, or `null`).
2. The server verifies the signature recovers to `signerAddress`. If
   `contractAddress` is non-null, it calls `IdentityContract.isAuthorized(signerAddress)`
   **on-chain** — the chain is truth.
3. On success it issues the signed `_epistery` cookie, recording `signerAddress`
   and (if verified) `contractAddress`. The auth middleware then exposes
   `req.episteryClient.identityAddress = contractAddress || signerAddress`.

A rivet is bound to a contract client-side via `wallet.upgradeToContract(contract)`
— afterward the wallet's derived `identityAddress` is the contract while
`signerAddress` is still the rivet. A fresh key exchange follows; the witness
short-circuits when (and only when) the cookie's `identityAddress` already
matches the wallet's `identityAddress`. The rivet→contract relation in
localStorage is not cryptographically sealed in the browser — but spoofing it
is useless: the contract knows its authorized signers and can't be spoofed; the
on-chain verification at `/connect` is the gate.

---

## HTTP interface

Mounted under `rootPath` (default `/.well-known/epistery`, RFC 8615):

| Path | Methods | Purpose |
|------|---------|---------|
| `/` | GET | Server status JSON (`Witness.connect` probes this for chain/provider info). No HTML UI. |
| `/lib/:module` | GET | Client libraries (`witness.js`, `wallet.js`, `client.js`, `ethers.js`, …) |
| `/artifacts/:file` | GET | Contract ABIs/artifacts |
| `/connect` | GET / POST | Session check / key-exchange handshake (sets `_epistery`; on-chain `isAuthorized` verify for contract claims) |
| `/fido/blob`, `/fido/blob/:credentialId` | POST/GET | PRF-wrapped rivet key blob storage |

---

## Server API

```javascript
import { Epistery, Config } from 'epistery';

const epistery = await Epistery.connect({
  authentication:  async (clientInfo) => { /* return profile or null */ },
  onAuthenticated: async (clientInfo, req, res) => { /* post-auth hook */ },
});
await epistery.setDomain('mydomain.com');
await epistery.attach(app);              // mounts middleware + routes under rootPath
```

A host is one identity: the domain pinned with `setDomain` is the domain of
every request, and a host that pinned none answers 503 rather than taking its
identity from the first Host header. A multi-domain host that serves one
identity per hostname from a single process asks for that explicitly:
`attach(app, rootPath, { domains: 'request' })`.

The `clientInfo` passed to both hooks has the same shape as
`req.episteryClient`: `{ signerAddress, contractAddress, identityAddress,
publicKey }` (plus `authenticated` and `profile` after `authentication`
resolves). Authorize against `identityAddress`.

`Epistery` (exported as `EpisteryAttach`): `connect`, `setDomain`, `attach`,
`resolveClient(req)` (auth resolution for non-middleware contexts, e.g. WebSocket
upgrades), `signer` (the domain's connected wallet — what every host-side
signature uses; nothing rebuilds a key from the mnemonic), `buildStatus`, `routes`.

Also exported: `verifyBotAuth`, `captureRawBody`, `sessionFromJar`, the nonce
stores (`setBotNonceStore`, `createInProcessNonceStore`, `createMongoNonceStore`);
`Config`, `auditTree`, `secureTree`; `CliWallet`; the chains (`chainFor`,
`registerChain`, `configuredChains`, `defaultChainId`, `defaultChain`, `findChain`,
`setDefaultChain`, `providerConfigFor`, `Chain`) and `attestationConfig`; the
reader (`chainReader`, `isChainReadFailure`, `ROLE`, `ROLE_NAME`, `roleName`);
and the wire (`storageWriteMessage` and the storage-message surface, `botAuthorization`,
`botAuthMessage`, `keyExchangeMessage`, the boost digest and `issueBoost`, the
origin certificate).

### The wire (core owns it)

Every shared definition of what goes over the wire lives in core and is imported
by every signer and verifier; none re-inlines it. Each is a pure ES module under
`client/`, importable in Node and servable to a browser (`/lib/<name>`):

- `client/storage-message.mjs` — the `/storage` signed write: `storageWriteMessage`
  and `parseStorageWriteMessage` (the six-line message), `encodeStorageCredential`
  / `decodeStorageCredential` (the `Bot <base64url {address, signature, message[,
  identity]}>` envelope, byte-identical to what is stored and verified today),
  `storageAuthorization`, `signStorageWrite` (build + sign with any `sign(message)`),
  `sha256hex` (the one body hash, WebCrypto), `ADDRESS_RE` / `isAddress`.
- `client/chain-read.mjs` — `chainReader` (k-of-n attestation reads over owned
  nodes: `isRivet`, `roleOf`, `sectionRole` (the two-hop through a vouching
  identity), `mayCommit`, `mayRotate`, `hasCode`, and `view` for any named
  function, `balanceOf` for the native balance, never cached; `observe`, when
  given, hears every read settle — `{ ok }` or `{ ok: false, code, message }`
  — so a host can make a refusal seen, not only thrown; every other verb
  takes `{ fresh }` to read past the cache; a node answers
  only while its head is fresh — its latest block younger than `maxHeadAgeMs`,
  2 minutes by default — so a node whose chain has stopped is a non-answer, not
  a confident old one), `isChainReadFailure`
  (the one classifier: a failed read is not a "no"), and `ROLE` / `ROLE_NAME` /
  `roleName`, the EpisteryAccess role table as the contract stores it (a test
  reads it out of the Solidity source).
- `client/key-exchange-message.mjs` — `keyExchangeMessage`, the string a device
  signs for `/connect` and for the config authority, and `serverResponseMessage`,
  the string the host signs back.
- `client/peer-cipher.mjs` — the one peer-encryption and content construction:
  a wrap is ECDH → SHA-256 → AES-256-GCM as `{ciphertext, iv, tag}` (tag split
  off); sealed content is AES-256-GCM under K as `{iv, ciphertext}` (tag
  appended). `wrapKey` / `unwrapKey` ask the wallet by capability (a rivet's
  `encryptForPeer`, or a plain wallet's key); `encryptText` / `decryptText`,
  `encryptBytes` / `decryptBytes`, `randomKey`. The wallet kinds in
  `client/wallet.js` and every cipher in the estate are built on it; a test
  freezes vectors from the previous server implementation.
- `client/bot-auth-message.mjs` — the bot-auth message and `botAuthorization`,
  which builds the whole `Authorization: Bot …` header for any signer
  (`sign(message)` + `address`); `CliWallet.createBotAuthHeader` delegates to it.
- `client/boost-message.mjs`, `client/origin-certificate.mjs` — as before.

`Config` reads distinguish absent from failed: a missing config is `{}`; a config
that cannot be read (filesystem error, authority error other than 404) throws.
The chain registry reads root config through one shared `Config`.

The core `Epistery` static API (`src/epistery.ts`): `initialize`,
`getStatus`, `handleKeyExchange` (consumed by `/connect`),
`submitSignedTransaction`
(generic broadcaster for client-signed transactions — this is the
"server-requests-signature, interactive wallet (FIDO/MetaMask) signs, then submit"
path).

### Config

Path-based ini config under `~/.epistery` (`src/utils/Config.ts`):

```javascript
import { Config } from 'epistery';
const config = new Config();
config.setPath('/');             // ~/.epistery/config.ini  (root)
config.load();
config.data.profile.email = 'user@example.com';
config.save();
config.setPath('/mydomain.com'); // ~/.epistery/mydomain.com/config.ini
```

Methods: `setPath`, `getPath`, `load`, `save` (+ `data`).

---

## Client API (`Witness`)

Served at `/.well-known/epistery/lib/witness.js`:

```javascript
import Witness from '/.well-known/epistery/lib/witness.js';
const witness = await Witness.connect({ rootPath: '/' }); // creates/loads wallet, runs key exchange
```

Public surface: `connect`, `performKeyExchange`, `getWallets`, `getStatus`,
`addBrowserWallet` / `addFidoWallet` / `addWeb3Wallet`, `setActiveWallet`,
`removeWallet`, `updateWalletLabel`, `bindToEpisteryIdentity` (cross-host identity
ferry). Wallet classes: `RivetWallet`, `FidoWallet`, `Web3Wallet`; binding via
`wallet.upgradeToContract`.

`setActiveWallet(id)` makes a rivet active **in the calling tab** and the device
default for tabs opened after it; other open tabs keep the rivet they loaded
with. Follow it with `performKeyExchange()` so the server session in this tab's
slot moves too. `setDefaultWallet` is the pre-tab name for it, kept working.
`getWallets()` reports both facts per wallet — `isActive` (what this tab is
being) and `isDefault` (what a new tab starts as) — plus `activeWalletId` and
`tabId`. See [Tab sessions](#tab-sessions--two-tabs-two-rivets).

**Paper backup (BIP39 phrase or passphrase):**

| Method | Purpose |
|--------|---------|
| `witness.generatePaperPhrase()` | A fresh 12-word BIP39 phrase to show the user once (the only copy). |
| `witness.paperRivetAddress(secret)` | Resolve a phrase **or** passphrase to `{ address, publicKey }` — authorize that address as a signer (via your on-chain `addRivet`) to register a backup. No wallet is stored. |
| `witness.recoverPaperIdentity(secret)` | Re-derive the rivet from the secret, re-home it as a durable non-extractable `RivetWallet`, and install it live + default. Follow with `performKeyExchange` and contract discovery/adopt to re-root on the identity. |

The underlying derivation is `RivetWallet.paperPrivateKeyFromInput(secret, ethers)`:
a standard-length valid BIP39 phrase is HD-derived (ethers default path); any
other non-empty string is a passphrase, PBKDF2-stretched (fixed app salt, 210k
iterations, SHA-256). Both are case- and whitespace-normalized, so the same
secret always resolves to the same address.

Identity properties on every wallet — the canonical surface for client code
deciding "who am I right now":

| Property              | Meaning |
|-----------------------|---------|
| `wallet.signerAddress`   | The rivet — the address we sign with. |
| `wallet.contractAddress` | The bound IdentityContract, or `null`. |
| `wallet.identityAddress` | Derived: `contractAddress || signerAddress`. What host UI and ACLs should reference. |

---

## CLI

The `epistery` command is its own package, [`@epistery/cli`](https://github.com/epistery/cli):

```bash
npm install -g @epistery/cli
epistery initialize -c polygon localhost
epistery curl https://api.example.com/data
epistery mcp https://epistery.com/p/wiki/<owner>/<session>   # a session, as its own member
```

It uses this package's public surface (`CliWallet`, `Config`, chain selection, key-file
modes), and it serves a console session's tools on the device through
`@epistery/plugins` — which is why it is not part of this package, which servers attach
as middleware and keeps to identity.

---

## Chains

Each EVM chain is a `Chain` object owning its RPC, fee policy, and gas strategy.
Only `chainId` is required; everything else comes from the class. Use
`chainFor({ chainId })`; add a chain by extending `Chain` + `registerChain()`.
A wallet's chain is chosen at `epistery initialize --chain <id|alias>` time and
stored in its domain config; `epistery set-chain <domain> <chain>` moves an
existing domain (keeping its wallet), and `epistery set-default-chain` sets what
new wallets get (Polygon mainnet out of the box).
See [src/chains/README.md](src/chains/README.md).

---

## Versioning & local development

- Consumers depend on the **published** package: `npm install epistery@latest`.
- Local cross-package work installs a **temporary relative path**
  (`npm install ../../rootz/epistery`) for testing only.
- Publishing to npm and any deployment is a deliberate, human-performed step. No
  tooling or agent publishes, bumps versions, or deploys on its own.

---

## Known divergences (audit)

Where the code currently fails the contract above. Dated; remove as fixed.

**Resolved in v1.2 (2026-05-27 identity-only refactor)**

- **Plaintext private keys.** `BrowserWallet` (extractable-key legacy wallet) is
  removed; `RivetWallet` WebCrypto fallback now **throws** rather than silently
  storing a plaintext key. No code path persists a cleartext signing key.
- **`agent.sol` surface.** Data wallets (`/data/*`), approvals (`/approval/*`),
  whitelist (`/whitelist/*`), on-chain lists/roles (`/lists`, `/list`), name
  registry (`resolveName`/`setAddressName`), `notabot`, contract creation
  (`/identity/prepare-deploy`), `contracts/` directory — all removed. epistery
  is now identity + storage/config + FIDO blob only.
- **Client header trust path.** Removed at the server boundary in v1.2: the
  middleware no longer reads `x-identity-contract`; identity is the verified
  identity epistery itself proved.

**Resolved in v1.2 follow-up (2026-05-28 naming cutover)**

- **Ambiguous identity vocabulary; no in-session rivet→contract upgrade.** The
  wire used `clientAddress` (alternately the signer or the identity), the
  server reconstructed which-was-meant on the fly, and `Witness.performKeyExchange`
  short-circuited by comparing the cookie's address to the signer — so a
  device that already had a rivet cookie could never have its session re-issued
  as contract-bound. Replaced with three distinct names everywhere: `signerAddress`
  (fact, asserted), `contractAddress` (claim, server-verified on-chain), and the
  derived `identityAddress` (= `contractAddress || signerAddress`, server-only).
  The witness short-circuits when (and only when) the cookie's `identityAddress`
  matches the wallet's `identityAddress`. The pre-cutover wire shape
  (`clientAddress` / `clientPublicKey`) is removed without aliases — old
  consumers fail at the handshake instead of silently degrading.

**Resolved in v2.3.0 (2026-09-06 bot-auth message binding)**

- **`Bot` auth was a bearer token.** `createBotAuthHeader()` signed the fixed
  string `"Rhonda Bot Authentication - <ISO ts>"` and the server checked only that
  the signature recovered the claimed address — no method, URI, audience, body
  digest, freshness or replay check. One captured header authorised any endpoint,
  on any epistery host, with any body, indefinitely. The signed bytes now come from
  `client/bot-auth-message.mjs` (same pattern as `storage-message.mjs`) and cover
  method + URI + audience host + body digest + timestamp + nonce. The pre-binding
  wire is removed without an alias: an old signer fails at the header rather than
  degrading silently.
- **Duplicated identity resolution.** `resolveClient()` and the `attach()`
  middleware each carried their own copy of bot verification. Both now call the
  single exported `verifyBotAuth()` — the README's rule that no consumer may
  re-derive identity applies to epistery itself first.

**Resolved in 2.4.x (2026-09-30, the 3Q26 refactor)**

- **Downstream identity bypass.** The consumer that asserted contract identity
  through a spoofable header was `epistery.app`, which is retired; the console
  reads identity only from `req.episteryClient.identityAddress`, as this
  document requires. The wire modules under `client/` (section "The wire") are
  imported by every signer and verifier in the estate and re-inlined nowhere;
  `Config` reads throw on failure rather than answering `{}`; the server-side
  funding and claiming routes (`/identity/prepare-add-rivet`, `/create`,
  `/auth/*`, `/domain/*`) are deleted.

**Outstanding**

1. **Wallet-internal `address` field still flips on upgrade.** `RivetWallet.upgradeToContract`
   still overwrites `wallet.address` with the contract address (the original
   rivet survives as `wallet.rivetAddress`). The new `wallet.signerAddress` /
   `wallet.identityAddress` getters cover the boundary, but every internal
   caller of `wallet.address` reads an overloaded value. Phase 1b: rename the
   persistence shape (with one-time IndexedDB migration so existing user
   wallets keep working) and convert call sites.

2. **`PrepareTransactionRequest`/`Response` types.** Reference removed
   `agent.sol` operations (`write` / `transferOwnership` / `createApproval`
   / etc.); imported but no longer consumed. Delete in the next dead-code sweep.

---

## License

MIT — see [LICENSE](LICENSE).

## Links

- Repository: https://github.com/rootz-global/epistery
- See [@epistery/cli](https://github.com/epistery/cli) and the Rootz library (EpisteryCore, EpisteryChainReads)