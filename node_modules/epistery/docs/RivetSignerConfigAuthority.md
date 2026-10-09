# Rivet Signer & Config Authority — Interface Spec

Status: draft for review · 2026-06-23 · feeds RootzOracleTenancy · repo: `epistery-authority` (instance `epistery-authority-1`)

This specifies the **interfaces** for turning `~/.epistery` local state into a shared
configuration/key authority, so pool members become stateless and interchangeable.
Interfaces first — no implementation here. It is the contract the authority, the
`Config` rewrite, and the client/server signers all build against.

## 0. The one idea

A **rivet** is *an unextractable-but-usable signing identity*. The private key lives
with a **custodian** that never hands it out; callers get **signatures**, not keys.

This is already true client-side. `client/wallet.js` `RivetWallet` keeps the secp256k1
key encrypted under a non-extractable WebCrypto AES key in IndexedDB and only ever
decrypts it inside a function closure that signs and returns (`wallet.js:399-434`,
`446-490`); `FidoWallet` wraps the key with a WebAuthn-PRF-derived key in the Secure
Enclave (`wallet.js:1272-1316`). The key never escapes the custodian.

The **server rivet** is the same object with a different custodian: the domain wallet's
key lives in `epistery-authority-1` and is used via a signing RPC. Today that key is the
plaintext mnemonic in `~/.epistery/<domain>/config.ini`, and **six call sites
independently re-derive a wallet from it** — `Utils.ts:80`, `epistery.ts:109` & `:170`,
host `DomainChain.mjs:78` & `index.mjs:239`, `relay/index.mjs:141`
(plus `message-board` and `chat/` deploy scripts). That scatter is the parallel-channel
we are collapsing into one owner.

```
            custodian (holds key, never releases)        rivet (used via signatures)
client      WebCrypto/IndexedDB  |  FIDO Secure Enclave   RivetWallet | FidoWallet
server      epistery-config-1 (HSM/TPM)                   RemoteSigner (domain wallet)
```

The custodian/rivet split is the shared abstraction. The authority is to the server
rivet what the FIDO authenticator is to the client rivet.

## 1. `Rivet` — the capability interface (shared)

The narrow async contract every rivet satisfies, regardless of custodian. All methods
are async because a remote/HSM/FIDO custodian cannot answer synchronously.

```ts
export interface Rivet {
  readonly address: string;        // the rivet (signer) address — always present
  readonly publicKey: string;      // uncompressed secp256k1, 0x04…
  getAddress(): Promise<string>;
  signMessage(message: string | Uint8Array): Promise<string>;
  signTransaction(tx: UnsignedTransaction): Promise<string>;   // returns raw signed tx hex
  // Optional ECDH peer crypto — implemented by custodians that can compute a
  // shared secret without exposing the key (RivetWallet/FidoWallet do this today,
  // wallet.js:495-530, 1321-1331). The authority MAY offer it as an RPC.
  encryptForPeer?(peerPublicKey: string, plaintext: Uint8Array): Promise<EciesBlob>;
  decryptFromPeer?(peerPublicKey: string, blob: EciesBlob): Promise<Uint8Array>;
}
```

Notes:
- This intentionally matches ethers v5 `Signer`'s `getAddress`/`signMessage`/
  `signTransaction`. The **server realization of `Rivet` is an `ethers.Signer`**
  (`RemoteSigner extends ethers.Signer`) because every server caller already consumes
  a `Signer` (`Utils.InitServerWallet` returns `ethers.Wallet` today). So adopting
  `Rivet` on the server is a no-op at the call sites — only the construction changes.
- The **client `Wallet` hierarchy is adapted to `Rivet`**: drop the `ethers` argument
  threaded through `sign(message, ethers)`/`signTransaction(tx, ethers)` (the browser
  no-bundler quirk) by binding `ethers` at construction; expose `getAddress`. The
  identity getters (`signerAddress`, `identityAddress`, `wallet.js:36-44`) stay — they
  are an identity concern layered above signing, not part of `Rivet`.

## 2. Two server rivets, layered

| Rivet | Custodian | Unextractable | Purpose |
|---|---|---|---|
| **machine/device rivet** | the box's TPM (self-minted per instance, per the wiki) | yes (hardware) | authenticates *this host* to the authority |
| **domain server rivet** | `epistery-authority-1` | Phase 2: yes | the on-chain identity the authority wields *on behalf of* authorized machines |

A pool member never holds the domain key. It proves itself with its machine rivet, and
borrows the domain rivet's signature from the authority. **N stateless machines share
one on-chain domain identity without sharing its key** — the wiki's statelessness and
its security story in one sentence.

## 3. `Config` becomes async (breaking)

Decided: all clients upgrade; no sync-snapshot shim. `Config` keeps its path-based shape
(`src/utils/Config.ts`) but `load`/`save`/`setPath`/`read` become async fetch/push points;
`.data` reflects the last `await`ed load.

```ts
export interface ConfigStore {
  setPath(path: string): Promise<void>;   // was sync; now awaits a fetch in remote mode
  getPath(): string;
  load(): Promise<void>;
  read(path: string): Promise<any>;       // read without moving current path
  save(): Promise<void>;
  readFile(name: string): Promise<Buffer>;
  writeFile(name: string, data: string | Buffer): Promise<void>;
  exists(): Promise<boolean>;
  listPaths(): Promise<string[]>;
  data: any;                               // snapshot from the last load()
}
```

**Backend selection** happens in the `Config` constructor:
- If local `~/.epistery/config.ini` has `[authority] url=…`, or `EPISTERY_CONFIG_URL`
  is set → `RemoteConfig` (talks to `epistery-config-1`).
- Else → `LocalConfig` (today's filesystem behavior, unchanged).

The local file never disappears — in remote mode it shrinks to **bootstrap state**: the
authority URL and this machine's credential (its machine-rivet handle). That is the
"machine data" the wiki carves out and the only per-box state a pool member keeps.

**Public/secret split in the data model.** Today `[wallet]` co-mingles public
(`address`, `publicKey`) and secret (`mnemonic`, `privateKey`) — `types.ts:18-23`. The
authority must serve the public fields freely and treat the secret as custodied:

| Class | Examples | Phase 1 | Phase 2 |
|---|---|---|---|
| public config | provider, contract addresses, claim state, prefs | served R/W | served R/W |
| signing key | wallet mnemonic / privateKey | released | **never released — authority signs** |
| opaque secret blob | TLS cert+key, storj/S3, mongo password | released to authorized machines | released (governed safe; cannot be HSM'd) |

**The authority is also a safe.** `readFile`/`writeFile` already persist arbitrary
blobs (`Config.ts:151-163`), and `Config`'s `.ssl/<domain>` path is already in the path
model — so the authority is two things at once: an **HSM** for signing keys (never
released) and a **safe** for opaque blobs (governed release via `/file/*path/:name`).
Anything that is a *bearer* secret — a key the host must itself present to a third party
or to a TLS handshake — lives in the safe, because the authority can't wield it remotely
the way it wields an Ethereum signing key.

## 4. Authority HTTP API

Auth is the **rivet key-exchange already in the codebase** (`Epistery.handleKeyExchange`,
`epistery.ts:82-137`; wire shapes `KeyExchangeRequest`/`Response`, `types.ts:98-117`),
pointed at the authority. One mechanism, not a bespoke machine-auth.

```
POST /auth/challenge   { machineAddress }                  -> { challenge }
POST /auth/verify      { machineAddress, message, signature, publicKey }
                       message = "Epistery Key Exchange - <machineAddress> - <challenge>"
                                                            -> { token }            # session/bearer

# Config data (token-gated; ACL decides which paths this machine may see)
GET  /config/*path                                          -> { data }            # public fields only
PUT  /config/*path     { data }                             -> { ok }
GET  /config/*path/_paths                                   -> { paths: string[] }
GET  /file/*path/:name                                      -> bytes
PUT  /file/*path/:name                                       <- bytes

# Server rivet — public info always; key material governed
GET  /wallet/:domain                                        -> { address, publicKey }   # never the key
POST /sign/message     { domain, message }                  -> { signature }            # Phase 2
POST /sign/transaction { domain, tx }                       -> { signedTransaction }    # Phase 2
GET  /secret/:domain/:name                                  -> { value }                # governed release (storj/mongo)
```

Governance ("like a CA"): the authority's ACL — keyed on the **machine rivet** — decides
which domains a host may read and which signing ops it may request. That is the
authority's reason to exist over a network share.

## 5. `RemoteSigner` — server-side rivet realization (Phase 2)

```ts
class RemoteSigner extends ethers.Signer implements Rivet {
  constructor(domain, authorityClient, provider) { super(); /* … */ }
  async getAddress()              { return (await this.authority.wallet(this.domain)).address; }
  async signMessage(message)      { return this.authority.signMessage(this.domain, message); }
  async signTransaction(tx)       { return this.authority.signTransaction(this.domain, tx); }
  connect(provider)               { return new RemoteSigner(this.domain, this.authority, provider); }
  // sendTransaction is inherited: signTransaction (remote) then provider.broadcast (local) —
  // so RPC/broadcast stay on the host; only the signature is remote.
}
```

`Utils.InitServerWallet(domain)` is the **single owner** of "get a signer for this
domain." It returns a `LocalWallet` (today / Phase 1) or a `RemoteSigner` (Phase 2)
behind the same `ethers.Signer` type. The six scattered `fromMnemonic` sites all route
through it — that consolidation is Phase 0 and is what makes Phase 2 a transport swap
rather than a client rewrite.

## 6. How each consumer adapts

- **epistery-host** — `await` the new `Config`; reads domain config/claim state from the
  authority; gets its domain signer from `Utils.InitServerWallet` (already does, via
  `app.locals.epistery.signer`). `DomainChain.mjs:78` & `index.mjs:239` stop calling
  `fromMnemonic` and ask `Utils`. TLS certs are a separate workstream (see §8).
- **epistery-app** — minimal: `await` the root config reads (`relayUrl`, `helpOwner`);
  manifest signing already goes through `epistery.signer`, so no signer change.
- **relay** — **subordinate, not merged.** Keeps credit metering, broadcast, and on-chain
  identity *reads*. Its pool wallet (`index.mjs:141`) becomes a domain rivet custodied by
  the authority: drop `fromMnemonic`, fetch a signer from the authority. Relay then pools
  too.
- **cli** (`CliWallet.ts`) — `await` Config; `CliWallet.create/load` obtain signers via
  the same path instead of `fromMnemonic`/`new Wallet(privateKey)` (`CliWallet.ts:153-156`).

## 7. Invariants

1. One owner for "get a signer": `Utils.InitServerWallet`. No other site derives a wallet
   from key material.
2. The custodian never emits a signing key in Phase 2. `GET /wallet/:domain` returns
   address/publicKey only.
3. The rivet key-exchange is the only host↔authority auth mechanism.
4. `Rivet` is the shared capability; `ethers.Signer` is its server realization; the client
   `Wallet` hierarchy is adapted to it. No second signing abstraction.

## 8. Open gaps (call out, don't assume)

- **TLS certs — not a blocker.** Certs persist as-is through the safe (`writeFile`/
  `readFile` + `/file/.ssl/<domain>/…`), so the wiki's "certs live in the shared authority"
  goal needs no special machinery: a pool member fetches its cert+key blob and self-
  terminates TLS, NLB stays dumb L4. Certify/ACME (`@metric-im/administrate`) can keep
  issuing and just write the result into the safe. A more elegant SSL flow (authority-
  driven issuance/rotation) is possible later but is **not important now**.
- **Nonce/ordering.** Once one domain rivet signs for N hosts, transaction nonce management
  must centralize (at the authority or a per-domain sequencer) or concurrent hosts collide.
- **Availability.** The authority becomes a hard dependency for any signing host. Needs a
  bootstrap cache / degraded-mode policy decision.
- **rootz-v6 alignment.** This mirrors the identity-owned Secret pattern; align at the
  Solidity/interface level only, per standing guidance — no shared library yet.
```