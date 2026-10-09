/*
 * Wallet - Base class for client wallets
 *
 * Handles wallet creation, persistence, and signing for Epistery
 */

import { ecdhShared, aesKeyFromShared, sealWithKey, openWithKey } from "./peer-cipher.mjs";

// Base Wallet class
//
// Identity vocabulary (must match epistery's server-side contract):
//   - signerAddress   : the rivet — the key we sign with. Always non-null.
//   - contractAddress : an IdentityContract this signer speaks for, or null.
//   - identityAddress : the canonical identity. Derived: contractAddress
//                       || signerAddress. Never persisted; always computed.
//
// `address` is the rivet (device key) for the LIFE of the wallet — it is no
// longer flipped to the contract on upgrade. Identity decisions use the
// getters (signerAddress / identityAddress) or the explicit contractAddress
// field. Legacy records that were flipped before this change are un-flipped
// on load (see RivetWallet.fromJSON migration).
// (Phase 1b — future: rename the persisted `address` key to `rivetAddress`
// so the storage shape matches the vocabulary.)
export class Wallet {
  constructor() {
    this.address = null;
    this.publicKey = null;
    this.source = null;
    // RivetWallet sets these to real values; the base class defaults so
    // every wallet variant exposes the three-fact shape uniformly.
    this.contractAddress = null;
    this.rivetAddress = null;
    // Capability declaration: true when this wallet holds a rivet key that
    // implements encryptForPeer/decryptFromPeer. Consumers check THIS flag
    // — never the source name, never typeof (the base stubs below always
    // exist). Only a wallet whose key can actually run the ECDH sets it.
    this.canPeerEncrypt = false;
  }

  // The rivet. For wallets that have been upgraded to a contract,
  // `address` was flipped to the contract; the original rivet is kept on
  // `rivetAddress`. For unbound wallets the rivet IS `address`.
  get signerAddress() {
    return this.rivetAddress || this.address;
  }

  // The canonical identity — what host ACLs evaluate against. Derived
  // from facts; never stored.
  get identityAddress() {
    return this.contractAddress || this.signerAddress;
  }

  // Serialize only the essential data for persistence
  toJSON() {
    return {
      address: this.address,
      publicKey: this.publicKey,
      source: this.source,
      // Contract binding is a base-class fact — persist it for EVERY rivet
      // kind, or adopting an identity silently unbinds on reload.
      contractAddress: this.contractAddress,
      rivetAddress: this.rivetAddress,
    };
  }

  // Bind this rivet to an identity contract. A base-class capability: any
  // rivet kind (browser, FIDO, web3) can be a signer on a contract. Does
  // NOT flip `address` — the device key stays `address`/`rivetAddress`;
  // the contract is a separate fact exposed via contractAddress /
  // identityAddress.
  upgradeToContract(contractAddress) {
    if (this.contractAddress) {
      throw new Error("Rivet is already using an identity contract");
    }
    this.rivetAddress = this.address;
    this.contractAddress = contractAddress;
  }

  // Factory method to create appropriate wallet type from saved data.
  // The three rivet types — web3, browser (rivet), and fido — are the only
  // valid identities. Anything else is a legacy/unsupported entry (e.g. the
  // pre-2.0 plaintext "local" browser wallet, which is NOT a rivet). Return
  // null rather than throw so one dead entry can't abort the whole load; the
  // caller skips and purges it.
  static async fromJSON(data, ethers) {
    if (data.source === "web3") {
      return await Web3Wallet.fromJSON(data, ethers);
    } else if (data.source === "rivet") {
      return await RivetWallet.fromJSON(data, ethers);
    } else if (data.source === "fido") {
      return await FidoWallet.fromJSON(data, ethers);
    }
    console.warn(`[epistery] Ignoring unsupported wallet source: ${data.source}`);
    return null;
  }

  // Abstract methods - must be implemented by subclasses
  async sign(message) {
    throw new Error("sign() must be implemented by subclass");
  }

  static async create(ethers) {
    throw new Error("create() must be implemented by subclass");
  }

  // Peer encryption (ECDH + AES-256-GCM) — optional capability. Wallets
  // that hold their private key in a closure (RivetWallet, FidoWallet)
  // implement these so plaintext callers never see the key.
  // Wire format: secp256k1 ECDH → SHA-256 → AES-GCM(iv:12, tag:16). The
  // shared secret + private key live only inside the implementing closure.
  async encryptForPeer(peerPublicKey, plaintextBytes, ethers) {
    throw new Error(`${this.source} wallet does not support peer encryption`);
  }

  async decryptFromPeer(peerPublicKey, ciphertextBytes, ivBytes, tagBytes, ethers) {
    throw new Error(`${this.source} wallet does not support peer decryption`);
  }

  // Raw ECDH shared secret — optional capability, implemented by data-capable
  // wallets (RivetWallet, Web3Wallet). The TreeKEM leaf-decap seam needs the
  // shared secret BEFORE any KDF so it can run its own HKDF schedule; a
  // signing-only/legacy wallet fails loudly here rather than silently.
  async computeSharedSecret(peerPublicKey, ethers) {
    throw new Error(`${this.source} wallet does not support shared-secret derivation`);
  }
}

// The peer-encryption construction is core's one definition (peer-cipher.mjs):
// ECDH → SHA-256 → AES-256-GCM. These three names are what the wallet kinds
// below call with a private key that is briefly in scope; the shared secret and
// the derived key never leave the closure.
function _sharedFromPriv(privateKeyHex, peerPublicKeyHex, ethers) {
  return ecdhShared(privateKeyHex, peerPublicKeyHex, ethers);
}
async function _deriveAesKeyFromPriv(privateKeyHex, peerPublicKeyHex, ethers) {
  return aesKeyFromShared(_sharedFromPriv(privateKeyHex, peerPublicKeyHex, ethers));
}
const _aesGcmEncrypt = sealWithKey;
const _aesGcmDecrypt = openWithKey;

// Web3 Wallet — a RIVET locked by a plugin wallet (MetaMask, etc.).
//
// The common model: every wallet IS a nimble rivet key; the sources differ
// only in what LOCKS that key. RivetWallet's key is locked by the
// non-extractable WebCrypto master key; FidoWallet's by the authenticator's
// PRF secret; here the plugin wallet is the lock. The rivet private key is
// DERIVED from one deterministic personal_sign over a fixed message that
// binds BOTH the site (hostname) and the plugin account:
//
//   priv = keccak256( sign("epistery rivet key v1\n<hostname>\n<web3Address>…") )
//
// ECDSA in every major plugin wallet is RFC-6979 deterministic, so the same
// account on the same site always re-derives the same rivet — nothing
// secret is stored, and the rivet is recoverable on any device that holds
// the plugin wallet. Binding the hostname makes web3 rivets ORIGIN-SCOPED,
// exactly like browser rivets (whose keys live in origin-scoped
// localStorage) and consistent with the one-rivet-one-contract policy: a
// different site derives a different rivet, so identities don't link
// across sites — and a signature phished on another site derives that
// site's rivet, useless here. The wallet's ADDRESS and publicKey are the
// RIVET's; the plugin account is kept as `web3Address` (the lock, shown in
// UI, usable as a value/recovery signer on-chain). Everything a rivet does
// — sign, transact, peer encryption — runs on the derived key, unlocked
// once per session.
//
// Phishing note: only a page the user believes is <hostname> can obtain a
// useful signature. The message names the site and the account; plugin
// wallets display it verbatim. Same posture as the widely used
// signature-derived-key pattern (dYdX/StarkEx et al.), tightened by the
// hostname binding.
//
// Legacy records (pre-lock, address == plugin account, placeholder pubkey)
// load in a signing-only compatibility mode (`canPeerEncrypt` stays false);
// re-adding the plugin wallet mints the locked rivet.
const WEB3_LOCK_MESSAGE_V1 = (hostname, addr) =>
  `epistery rivet key v1\n${hostname}\n${addr.toLowerCase()}\n\nSigning this unlocks your epistery device key on ${hostname}. Only sign it on that site.`;

// The site component of the lock message. hostname (not origin/host): stable
// across ports and schemes so dev restarts don't orphan rivets, while still
// separating every domain.
function _lockHostname() {
  if (typeof window === "undefined" || !window.location || !window.location.hostname) {
    throw new Error("web3 rivets exist only in a browser context (no hostname to bind)");
  }
  return window.location.hostname.toLowerCase();
}

export class Web3Wallet extends Wallet {
  constructor() {
    super();
    this.source = "web3";
    this.web3Address = null;   // the plugin account that locks the rivet
    this.label = null;
    this.createdAt = null;
    this.signer = null;        // plugin signer (the lock) — session only
    this.provider = null;
    this._priv = null;         // unlocked rivet key — closure/session only
    this._legacy = false;      // pre-lock record: address IS the plugin account
    this.canPeerEncrypt = false;   // true once the rivet exists (locked mode)
  }

  toJSON() {
    // Nothing secret persists: the rivet re-derives from the plugin
    // signature on unlock. signer/provider/_priv are session-only.
    return {
      ...super.toJSON(),
      // A legacy record must round-trip as legacy: writing web3Address
      // would dress it up as a locked rivet it never minted.
      web3Address: this._legacy ? null : this.web3Address,
      label: this.label,
      createdAt: this.createdAt,
    };
  }

  static async fromJSON(data, ethers) {
    const wallet = new Web3Wallet();
    wallet.address = data.address;
    wallet.publicKey = data.publicKey;
    // Locked-rivet records carry web3Address. Legacy pre-lock records don't:
    // their address IS the plugin account and no rivet was ever minted —
    // they stay signing-only (the plugin signs directly) until re-added.
    wallet._legacy = !data.web3Address;
    wallet.web3Address = data.web3Address || data.address;
    wallet.label = data.label || null;
    wallet.createdAt = data.createdAt || null;
    wallet.contractAddress = data.contractAddress || null;
    wallet.rivetAddress = data.rivetAddress || null;
    wallet.canPeerEncrypt = !wallet._legacy;
    // Lazy: the plugin reconnect + unlock signature happen on first use,
    // not at restore — a locked wallet still reports address/publicKey.
    return wallet;
  }

  static async create(ethers) {
    const wallet = new Web3Wallet();
    try {
      if (!(await wallet._connectPlugin(ethers))) return null;
      await wallet._unlock(ethers);   // derives + installs the rivet
      wallet.createdAt = Date.now();
      return wallet;
    } catch (error) {
      console.warn("Web3Wallet.create failed:", error.message);
      return null;   // user declined, or no plugin wallet available
    }
  }

  async _connectPlugin(ethers) {
    if (typeof window === "undefined" || !(window.ethereum || window.web3)) {
      return false;
    }
    const provider = window.ethereum || window.web3.currentProvider;
    const accounts = await provider.request({ method: "eth_requestAccounts" });
    if (!accounts || !accounts.length) return false;
    this.provider = new ethers.providers.Web3Provider(provider);
    this.signer = this.provider.getSigner();
    if (!this.web3Address) this.web3Address = accounts[0];
    if (accounts[0].toLowerCase() !== this.web3Address.toLowerCase()) {
      throw new Error(
        `This wallet is locked by ${this.web3Address} — switch the plugin wallet to that account to unlock it`,
      );
    }
    return true;
  }

  // Unlock: one deterministic plugin signature → the rivet key, cached for
  // the session. Verifies against the stored rivet address so a different
  // plugin account (different derivation) fails closed instead of silently
  // becoming a different rivet.
  async _unlock(ethers) {
    if (this._legacy) {
      throw new Error("legacy web3 wallet has no rivet — remove and re-add it to mint one");
    }
    if (this._priv) return this._priv;
    if (!this.signer && !(await this._connectPlugin(ethers))) {
      throw new Error("Plugin wallet not available — connect it to unlock this rivet");
    }
    const signature = await this.signer.signMessage(
      WEB3_LOCK_MESSAGE_V1(_lockHostname(), this.web3Address),
    );
    const priv = ethers.utils.keccak256(ethers.utils.arrayify(signature));
    const signingKey = new ethers.utils.SigningKey(priv);
    const address = ethers.utils.computeAddress(signingKey.publicKey);
    if (this.address && address.toLowerCase() !== this.address.toLowerCase()) {
      throw new Error(
        "Unlock produced a different rivet — sign with the plugin account that created this wallet",
      );
    }
    this._priv = priv;
    this.address = address;
    this.publicKey = signingKey.publicKey;   // real uncompressed secp256k1
    this.canPeerEncrypt = true;
    return priv;
  }

  async sign(message, ethers) {
    if (this._legacy) {
      // Pre-lock record: its address IS the plugin account, which may
      // already be a rivet on an IdentityContract — it must keep signing
      // (that's how the owner authorizes adding a locked rivet later).
      if (!this.signer && !(await this._connectPlugin(ethers))) {
        throw new Error("Plugin wallet not available");
      }
      return await this.signer.signMessage(message);
    }
    const priv = await this._unlock(ethers);
    return await new ethers.Wallet(priv).signMessage(message);
  }

  async signTransaction(unsignedTx, ethers) {
    if (this._legacy) {
      // Plugin signers can't produce raw signed txs (and never could here).
      throw new Error("legacy web3 wallet cannot sign transactions — remove and re-add it to mint its locked rivet");
    }
    const priv = await this._unlock(ethers);
    return await new ethers.Wallet(priv).signTransaction(unsignedTx);
  }

  async encryptForPeer(peerPublicKey, plaintextBytes, ethers) {
    if (!this.canPeerEncrypt) {
      throw new Error("legacy web3 wallet — remove and re-add it to mint its locked rivet");
    }
    const priv = await this._unlock(ethers);
    const aesKey = await _deriveAesKeyFromPriv(priv, peerPublicKey, ethers);
    return await _aesGcmEncrypt(aesKey, plaintextBytes);
  }

  async decryptFromPeer(peerPublicKey, ciphertextBytes, ivBytes, tagBytes, ethers) {
    if (!this.canPeerEncrypt) {
      throw new Error("legacy web3 wallet — remove and re-add it to mint its locked rivet");
    }
    const priv = await this._unlock(ethers);
    const aesKey = await _deriveAesKeyFromPriv(priv, peerPublicKey, ethers);
    return await _aesGcmDecrypt(aesKey, ciphertextBytes, ivBytes, tagBytes);
  }

  // Raw ECDH shared secret for the TreeKEM leaf-decap seam. The locked rivet key
  // is derived from the plugin signature in _unlock and used in-closure.
  async computeSharedSecret(peerPublicKey, ethers) {
    if (!this.canPeerEncrypt) {
      throw new Error("legacy web3 wallet — remove and re-add it to mint its locked rivet");
    }
    const priv = await this._unlock(ethers);
    return _sharedFromPriv(priv, peerPublicKey, ethers);
  }
}


// Rivet Wallet (Non-extractable browser wallet)
export class RivetWallet extends Wallet {
  constructor() {
    super();
    this.source = "rivet";
    this.canPeerEncrypt = true;
    this.keyId = null;
    this.type = "Browser"; // Browser, Contract, or Web3
    this.label = null;
    this.provider = null;
    this.createdAt = null;
    this.lastUpdated = null;
    this.encryptedPrivateKey = null;
    this.contractAddress = null; // If upgraded to IdentityContract
    this.rivetAddress = null; // Original rivet address (if using contract)
    this.associations = []; // Associated keys (e.g., Web3 wallet as second factor)
  }

  toJSON() {
    return {
      ...super.toJSON(),
      keyId: this.keyId,
      type: this.type,
      label: this.label,
      provider: this.provider,
      createdAt: this.createdAt,
      lastUpdated: this.lastUpdated,
      encryptedPrivateKey: this.encryptedPrivateKey,
      associations: this.associations,
    };
  }

  static async fromJSON(data, ethers) {
    const wallet = new RivetWallet();
    wallet.address = data.address;
    wallet.publicKey = data.publicKey;
    wallet.keyId = data.keyId;
    wallet.type = data.type || "Browser";
    wallet.label = data.label;
    wallet.provider = data.provider;
    wallet.createdAt = data.createdAt;
    wallet.lastUpdated = data.lastUpdated;
    wallet.encryptedPrivateKey = data.encryptedPrivateKey;
    wallet.contractAddress = data.contractAddress;
    wallet.rivetAddress = data.rivetAddress;
    wallet.associations = data.associations || [];

    // Migrate legacy flipped records. Before we stopped flipping, upgradeToContract
    // set `address = contractAddress` and stashed the rivet on rivetAddress. Restore
    // `address` to the rivet so it's always the device key. Unambiguous: only an old
    // flipped record has address === contractAddress with a distinct rivetAddress.
    // New (unflipped) records have address === rivetAddress !== contractAddress and
    // are left untouched. Re-saving the wallet persists the corrected shape.
    if (
      wallet.contractAddress &&
      wallet.rivetAddress &&
      wallet.address &&
      wallet.address.toLowerCase() === wallet.contractAddress.toLowerCase()
    ) {
      wallet.address = wallet.rivetAddress;
    }

    return wallet;
  }

  static async create(ethers) {
    // A fresh browser rivet is a random secp256k1 key put through the standard
    // rivet custody (fromPrivateKey). Kept as a thin alias so there is one owner
    // of "wrap a key under a non-extractable master key" — the mint path and the
    // paper-backup recovery path can't drift apart.
    return await RivetWallet.fromPrivateKey(
      ethers.Wallet.createRandom().privateKey,
      ethers,
      "Browser Wallet",
    );
  }

  // Wrap an EXISTING secp256k1 private key as a non-extractable browser rivet —
  // the same custody as create(), but for a key supplied from elsewhere rather
  // than freshly randomised. This is how a paper (BIP39) backup is RE-HOMED onto
  // a device on recovery: the phrase re-derives the key, that key is encrypted
  // under a fresh non-extractable master key here, and the caller then discards
  // the plaintext key and the phrase. The stored rivet is indistinguishable from
  // one minted by create() (source "rivet") — no new wallet type, no secret ever
  // persisted in the clear.
  static async fromPrivateKey(privateKeyHex, ethers, label = "Browser Wallet") {
    const wallet = new RivetWallet();

    try {
      // Generate unique keyId
      wallet.keyId =
        "rivet-" + Date.now() + "-" + Math.random().toString(36).substr(2, 9);
      wallet.createdAt = Date.now();
      wallet.lastUpdated = Date.now();
      wallet.label = label;

      // The unextractable-key guarantee REQUIRES Web Crypto. If it's missing,
      // refuse — Epistery never persists an extractable private key.
      if (!window.crypto || !window.crypto.subtle) {
        throw new Error(
          "Web Crypto API unavailable: cannot create a secure (unextractable) rivet wallet.",
        );
      }

      // Derive the address/publicKey from the supplied key. (createRandom gives
      // these for free; a re-homed paper key needs them computed.)
      const signingKey = new ethers.utils.SigningKey(privateKeyHex);
      wallet.address = ethers.utils.computeAddress(signingKey.publicKey);
      wallet.publicKey = signingKey.publicKey;

      // Generate non-extractable AES-GCM key for encrypting the secp256k1 private key
      const masterKey = await crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: 256,
        },
        false, // non-extractable!
        ["encrypt", "decrypt"],
      );

      // Store master key in IndexedDB (non-extractable CryptoKey)
      await RivetWallet.storeMasterKey(wallet.keyId, masterKey);

      // Encrypt the private key with the master key
      const privateKeyBytes = ethers.utils.arrayify(privateKeyHex);
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        masterKey,
        privateKeyBytes,
      );

      // Store encrypted private key and IV
      wallet.encryptedPrivateKey = JSON.stringify({
        encrypted: ethers.utils.hexlify(new Uint8Array(encryptedBuffer)),
        iv: ethers.utils.hexlify(iv),
      });

      return wallet;
    } catch (error) {
      console.error("Failed to create rivet wallet:", error);
      throw error;
    }
  }

  // --- Paper backup rivets (BIP39 phrase OR passphrase) ----------------------
  // A "paper" rivet is an ordinary secp256k1 rivet whose key is derived from a
  // secret the human holds OFFLINE — the backup signer with no agency on any
  // device until it is reconstructed. Two kinds of secret are accepted, detected
  // deterministically so backup and recovery always agree:
  //   • a valid BIP39 phrase (what generatePaperPhrase produces) → HD-derived at
  //     the ethers default path;
  //   • ANY other non-empty string — a human passphrase like "peanut butter" —
  //     → stretched with PBKDF2 into the key (a brainwallet). Deliberately weaker
  //     than a generated phrase (guessable if short/common); the user's tradeoff
  //     for something memorable.
  // The secret↔rivet mapping lives here so it has one owner; the witness composes
  // these into add-backup / recover, and a recovered secret is re-homed as a
  // normal browser rivet via fromPrivateKey. (EpisteryCore: "Recovery is another
  // signer on the same contract, never a custodian" — the paper secret is that
  // other signer, held by the human.)

  // A fresh 12-word BIP39 phrase (ethers' own English wordlist). This is the
  // ONLY copy the user gets — callers show it once and advise writing it down.
  static generatePaperPhrase(ethers) {
    return ethers.Wallet.createRandom().mnemonic.phrase;
  }

  // Resolve a backup secret to a private key, branching on what it is (see the
  // section header). normalizePaperPhrase makes both kinds case- and whitespace-
  // insensitive, so a human need not reproduce exact spacing or capitalization.
  // Throws only on empty input — any non-empty string is a usable passphrase.
  static async paperPrivateKeyFromInput(secret, ethers) {
    const normalized = RivetWallet.normalizePaperPhrase(secret);
    if (!normalized) throw new Error("Enter a backup phrase or passphrase.");
    // Treat as a BIP39 phrase only at a STANDARD word count — ethers'
    // isValidMnemonic also accepts short (3/6/9-word) checksum coincidences that
    // fromMnemonic then rejects ("invalid entropy"), which would crash a human
    // passphrase like "peanut butter jelly". Gating on length routes every real
    // passphrase to the brainwallet branch below.
    const wordCount = normalized.split(" ").length;
    if (
      [12, 15, 18, 21, 24].includes(wordCount) &&
      ethers.utils.isValidMnemonic(normalized)
    ) {
      return ethers.Wallet.fromMnemonic(normalized).privateKey;
    }
    // Otherwise it is a passphrase. Minimal rules only — a length floor and a
    // character set; how strong it is beyond that is the user's call, not ours.
    if (normalized.length < 10) {
      throw new Error("Passphrase must be at least 10 characters.");
    }
    if (!/^[ -~]+$/.test(normalized)) {
      throw new Error("Passphrase may use only letters, numbers, spaces and punctuation.");
    }
    // Passphrase brainwallet: PBKDF2(secret, fixed app salt, 210k, SHA-256) → a
    // 32-byte private key. The salt is a FIXED constant (not per-user) because
    // recovery has only the passphrase — determinism is the whole point; the
    // iterations just raise an attacker's per-guess cost. Versioned so the
    // derivation can change later without breaking existing backups (a v2 would
    // be a new branch, not an edit to this one).
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(normalized),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: enc.encode("epistery/paper-passphrase/v1"),
        iterations: 210000,
        hash: "SHA-256",
      },
      baseKey,
      256,
    );
    return ethers.utils.hexlify(new Uint8Array(bits));
  }

  // Derive the rivet identity (address + public key) from a backup secret WITHOUT
  // building or storing a wallet — Add backup authorizes this address on-chain,
  // then discards everything. Deterministic: the same secret always resolves to
  // the same address (a generated phrase and its re-entry, or a passphrase and
  // its re-entry).
  static async paperAddressFromPhrase(secret, ethers) {
    const priv = await RivetWallet.paperPrivateKeyFromInput(secret, ethers);
    const signingKey = new ethers.utils.SigningKey(priv);
    return {
      address: ethers.utils.computeAddress(signingKey.publicKey),
      publicKey: signingKey.publicKey,
    };
  }

  // Reconstruct a DURABLE device rivet from a backup secret (Recover identity):
  // the key is re-homed under a fresh non-extractable master key on THIS device,
  // exactly like any browser rivet — the secret is then pure offline backup.
  static async fromPhrase(secret, ethers, label = "Recovered Wallet") {
    const priv = await RivetWallet.paperPrivateKeyFromInput(secret, ethers);
    return await RivetWallet.fromPrivateKey(priv, ethers, label);
  }

  // Canonicalize a user-entered phrase: trim, collapse internal whitespace,
  // lowercase (the BIP39 English wordlist is lowercase). Generation already
  // yields this shape; hand entry may not.
  static normalizePaperPhrase(phrase) {
    return String(phrase || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, " ");
  }

  // The ONE place the rivet's private key is unlocked. The master key is a
  // non-extractable WebCrypto key in IndexedDB; the private key is decrypted
  // under it into this closure, handed to `use`, and goes out of scope when
  // `use` returns. Every signing and peer-crypto method runs through here.
  async _withPrivateKey(ethers, use) {
    const masterKey = await RivetWallet.getMasterKey(this.keyId);
    if (!masterKey) {
      throw new Error(
        "Master key not found - rivet may have been created in a different browser context",
      );
    }
    const { encrypted, iv } = JSON.parse(this.encryptedPrivateKey);
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ethers.utils.arrayify(iv) },
      masterKey,
      ethers.utils.arrayify(encrypted),
    );
    const privateKey = ethers.utils.hexlify(new Uint8Array(decryptedBuffer));
    return use(privateKey);
  }

  /** Sign a message with the rivet. */
  async sign(message, ethers) {
    return this._withPrivateKey(ethers, async (privateKey) => new ethers.Wallet(privateKey).signMessage(message));
  }

  /** Sign a complete transaction with the rivet; the key must match the rivet's address. */
  async signTransaction(unsignedTx, ethers) {
    return this._withPrivateKey(ethers, async (privateKey) => {
      const signer = new ethers.Wallet(privateKey);
      const addressToValidate = this.rivetAddress || this.address;
      if (signer.address.toLowerCase() !== addressToValidate.toLowerCase()) {
        throw new Error("Decrypted key does not match rivet address");
      }
      return signer.signTransaction(unsignedTx);
    });
  }

  // Peer encryption and the TreeKEM leaf-decap seam, each one unlock.
  async encryptForPeer(peerPublicKey, plaintextBytes, ethers) {
    return this._withPrivateKey(ethers, async (privateKey) =>
      _aesGcmEncrypt(await _deriveAesKeyFromPriv(privateKey, peerPublicKey, ethers), plaintextBytes));
  }

  async decryptFromPeer(peerPublicKey, ciphertextBytes, ivBytes, tagBytes, ethers) {
    return this._withPrivateKey(ethers, async (privateKey) =>
      _aesGcmDecrypt(await _deriveAesKeyFromPriv(privateKey, peerPublicKey, ethers), ciphertextBytes, ivBytes, tagBytes));
  }

  // Raw ECDH shared secret, BEFORE any KDF, so the ratchet tree runs its own schedule.
  async computeSharedSecret(peerPublicKey, ethers) {
    return this._withPrivateKey(ethers, async (privateKey) => _sharedFromPriv(privateKey, peerPublicKey, ethers));
  }

  // IndexedDB operations for storing non-extractable CryptoKey
  static async storeMasterKey(keyId, masterKey) {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open("EpisteryRivets", 1);

      request.onerror = () => reject(request.error);

      request.onsuccess = () => {
        const db = request.result;
        // Strict durability: the browser must fsync this write before the
        // transaction completes. Default (relaxed) durability acknowledges the
        // commit before it reaches disk, so an unclean shutdown (browser quit,
        // sleep, power loss) silently rolls the master key back — leaving the
        // wrapped private key with no key to unlock it. This key is the sovereign
        // root; it does not get to be best-effort.
        const transaction = db.transaction(["masterKeys"], "readwrite", { durability: "strict" });
        const store = transaction.objectStore("masterKeys");

        store.put({ keyId, masterKey });

        // Resolve on COMMIT, not on the put succeeding. putRequest.onsuccess fires
        // when the write is staged in the transaction; transaction.oncomplete
        // fires only once it has durably committed. Reporting "stored" before
        // commit is the born-orphaned bug (#30) — a rivet whose master key was
        // never actually persisted.
        transaction.oncomplete = () => { db.close(); resolve(); };
        transaction.onerror = () => { db.close(); reject(transaction.error); };
        transaction.onabort = () => {
          db.close();
          reject(transaction.error || new Error("storeMasterKey: transaction aborted before commit"));
        };
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains("masterKeys")) {
          db.createObjectStore("masterKeys", { keyPath: "keyId" });
        }
      };
    });
  }

  static async getMasterKey(keyId) {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open("EpisteryRivets", 1);

      request.onerror = () => reject(request.error);

      request.onsuccess = () => {
        const db = request.result;
        const transaction = db.transaction(["masterKeys"], "readonly");
        const store = transaction.objectStore("masterKeys");

        const getRequest = store.get(keyId);

        getRequest.onsuccess = () => {
          db.close();
          resolve(getRequest.result ? getRequest.result.masterKey : null);
        };

        getRequest.onerror = () => {
          db.close();
          reject(getRequest.error);
        };
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains("masterKeys")) {
          db.createObjectStore("masterKeys", { keyPath: "keyId" });
        }
      };
    });
  }

  // Identity Contract methods (opt-in, not automatic)

  /**
   * Upgrades this rivet to use an identity contract
   * @param {string} contractAddress - The deployed identity contract address
   */
  upgradeToContract(contractAddress) {
    super.upgradeToContract(contractAddress);
    this.type = "Contract";
    this.lastUpdated = Date.now();
  }
}

// Expose RivetWallet globally for browser access
if (typeof window !== "undefined") {
  window.RivetWallet = RivetWallet;
}

// FIDO/WebAuthn Wallet — PRF-wraps-rivet
//
// The FIDO credential lives in the Secure Enclave (ITP-exempt on iOS).
// WebAuthn PRF output derives an AES-256 key that wraps a freshly-generated
// secp256k1 rivet private key. The encrypted blob may live locally in the
// wallet JSON and/or be backed up to the epistery server (keyed by credential
// ID and domain) so it survives iOS ITP IndexedDB purges. See
// EpisteryMobileIdentity for the full design and threat model.
const FIDO_PRF_INPUT = new TextEncoder().encode("epistery-fido-prf-v1");

export class FidoWallet extends Wallet {
  constructor() {
    super();
    this.source = "fido";
    this.canPeerEncrypt = true;
    this.credentialId = null; // base64url string
    this.encryptedPrivateKey = null; // JSON: { ciphertext, iv } as hex
    this.label = null;
    this.createdAt = null;
    this.lastUpdated = null;
    this._priv = null;         // unlocked rivet key — session only, never persisted.
                               // Cached like Web3Wallet/RivetWallet so the FIDO
                               // (Face ID / Touch ID) ceremony runs once per session
                               // instead of on every sign/encrypt/decrypt. Dies with
                               // the instance (fromJSON/create mint a fresh one).
  }

  toJSON() {
    return {
      ...super.toJSON(),
      credentialId: this.credentialId,
      encryptedPrivateKey: this.encryptedPrivateKey,
      label: this.label,
      createdAt: this.createdAt,
      lastUpdated: this.lastUpdated,
    };
  }

  static async fromJSON(data, ethers) {
    const wallet = new FidoWallet();
    wallet.address = data.address;
    wallet.publicKey = data.publicKey;
    wallet.credentialId = data.credentialId;
    wallet.encryptedPrivateKey = data.encryptedPrivateKey;
    wallet.label = data.label;
    wallet.createdAt = data.createdAt;
    wallet.lastUpdated = data.lastUpdated;
    wallet.contractAddress = data.contractAddress || null;
    wallet.rivetAddress = data.rivetAddress || null;
    return wallet;
  }

  static _b64uEncode(bytes) {
    const s = btoa(String.fromCharCode(...new Uint8Array(bytes)));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  static _b64uDecode(s) {
    let padded = s.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // Registration ceremony: create credential, derive PRF, return both.
  // Some authenticators don't return PRF on create() — follow up with get().
  //
  // `excludeCredentials` (base64url credential ids we already know about) makes
  // the authenticator REFUSE to mint a duplicate for a credential this device
  // already holds — so re-running the offer while a passkey is still known does
  // not proliferate passkeys. It can only exclude ids we can see locally; the
  // post-purge case (no local ids) is handled by recover(), not here.
  //
  // residentKey is "required" (not "preferred") so the passkey is DISCOVERABLE:
  // recover() asserts with an empty allowCredentials list, which only surfaces
  // resident credentials. Without this, a purged device couldn't find its own
  // passkey to reference and would be pushed to mint a new one.
  static async _prfDeriveOnCreate(label, excludeCredentials = []) {
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Epistery", id: window.location.hostname },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: label || "epistery-user",
          displayName: label || "Epistery user",
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -257 }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "required",
        },
        excludeCredentials: (excludeCredentials || [])
          .filter(Boolean)
          .map((id) => ({ type: "public-key", id: FidoWallet._b64uDecode(id) })),
        extensions: {
          prf: { eval: { first: FIDO_PRF_INPUT } },
        },
      },
    });

    let prfOutput =
      credential.getClientExtensionResults()?.prf?.results?.first;

    if (!prfOutput) {
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          allowCredentials: [{ type: "public-key", id: credential.rawId }],
          userVerification: "required",
          extensions: { prf: { eval: { first: FIDO_PRF_INPUT } } },
        },
      });
      prfOutput =
        assertion.getClientExtensionResults()?.prf?.results?.first;
    }

    if (!prfOutput) {
      throw new Error(
        "Authenticator did not return PRF output — extension unsupported",
      );
    }

    return {
      credentialId: FidoWallet._b64uEncode(credential.rawId),
      prfBytes: new Uint8Array(prfOutput),
    };
  }

  // Unlock ceremony: prompt for credential, return PRF output.
  static async _prfDeriveOnGet(credentialId) {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [
          { type: "public-key", id: FidoWallet._b64uDecode(credentialId) },
        ],
        userVerification: "required",
        extensions: { prf: { eval: { first: FIDO_PRF_INPUT } } },
      },
    });

    const prfOutput =
      assertion.getClientExtensionResults()?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error("PRF output missing from authenticator assertion");
    }
    return new Uint8Array(prfOutput);
  }

  // Discovery ceremony: assert WITHOUT naming a credential (empty
  // allowCredentials) so the platform surfaces the user's existing discoverable
  // passkeys for this RP. Returns the chosen credential's id AND its PRF output
  // — the basis for recover(): reference an existing passkey instead of minting
  // a new one. Rejects (NotAllowedError) if the user has no passkey here or
  // cancels — the caller falls back to create() for a genuine first registration.
  static async _prfAssertDiscoverable() {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [], // discoverable credentials only
        userVerification: "required",
        extensions: { prf: { eval: { first: FIDO_PRF_INPUT } } },
      },
    });

    const prfOutput =
      assertion.getClientExtensionResults()?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error("PRF output missing from authenticator assertion");
    }
    return {
      credentialId: FidoWallet._b64uEncode(assertion.rawId),
      prfBytes: new Uint8Array(prfOutput),
    };
  }

  static async _aesKeyFromPRF(prfBytes, usage) {
    return await crypto.subtle.importKey(
      "raw",
      prfBytes,
      { name: "AES-GCM" },
      false,
      usage,
    );
  }

  static _rootPath() {
    // The server mounts epistery routes at attach()'s rootPath, and other client
    // calls (witness /connect, /identity/*) address them off that SAME base —
    // which is "" when the app attaches at site root (the console does
    // Witness.connect({rootPath:'/'}), normalized to ""). Preserve "" (a valid
    // base meaning site root); only fall back to ".." when Witness is unavailable.
    // A prior `|| ".."` swallowed "" and sent blob requests to the wrong origin-
    // relative path — the server-backup then 404'd silently ("blob is local-only").
    const rp =
      typeof Witness !== "undefined" ? Witness.instance?.rootPath : undefined;
    return rp === undefined || rp === null ? ".." : rp;
  }

  static async create(ethers, options = {}) {
    if (!window.PublicKeyCredential || !navigator.credentials?.create) {
      throw new Error("WebAuthn not available in this browser");
    }
    const label = options.label || "FIDO Wallet";
    // Register a NEW passkey (or refuse to duplicate one we already know about),
    // then wrap a fresh rivet under its PRF secret.
    const { credentialId, prfBytes } = await FidoWallet._prfDeriveOnCreate(
      label,
      options.excludeCredentials || [],
    );
    return await FidoWallet._wrapNewRivet(ethers, {
      credentialId,
      prfBytes,
      label,
      skipServerBackup: options.skipServerBackup,
    });
  }

  // Mint a fresh secp256k1 rivet, AES-GCM-wrap its private key with the PRF
  // secret of the given (already-asserted-or-registered) FIDO credential, back
  // the ciphertext up to the epistery server, and return a ready FidoWallet with
  // the key cached in _priv. Sole owner of "wrap a rivet under a FIDO credential"
  // — shared by create() (fresh passkey) and recover() (existing passkey whose
  // server blob is gone), so the two paths can never drift apart.
  static async _wrapNewRivet(ethers, { credentialId, prfBytes, label, skipServerBackup }) {
    const wallet = new FidoWallet();
    wallet.credentialId = credentialId;
    wallet.label = label || "FIDO Wallet";
    wallet.createdAt = Date.now();
    wallet.lastUpdated = wallet.createdAt;

    const aesKey = await FidoWallet._aesKeyFromPRF(prfBytes, ["encrypt"]);

    const ethersWallet = ethers.Wallet.createRandom();
    wallet.address = ethersWallet.address;
    wallet.publicKey = ethersWallet.publicKey;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const privateKeyBytes = ethers.utils.arrayify(ethersWallet.privateKey);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      privateKeyBytes,
    );

    const ciphertextHex = ethers.utils.hexlify(new Uint8Array(ciphertext));
    const ivHex = ethers.utils.hexlify(iv);

    wallet.encryptedPrivateKey = JSON.stringify({
      ciphertext: ciphertextHex,
      iv: ivHex,
    });
    wallet._priv = ethersWallet.privateKey; // session cache — no re-ceremony to sign now

    // Back up the encrypted blob to the epistery server so it survives
    // local storage purges (iOS ITP). The server holds ciphertext only.
    if (!skipServerBackup) {
      try {
        await fetch(`${FidoWallet._rootPath()}/fido/blob`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            credentialId: wallet.credentialId,
            rivetAddress: wallet.address,
            publicKey: wallet.publicKey,
            ciphertext: ciphertextHex,
            iv: ivHex,
            label: wallet.label,
          }),
        });
      } catch (e) {
        console.warn("FidoWallet: server backup failed, blob is local-only", e);
      }
    }

    return wallet;
  }

  // Recover a FIDO identity by REFERENCING an existing passkey instead of
  // minting a new one — the post-ITP-purge path EpisteryMobileIdentity specifies.
  // One Face ID / Touch ID:
  //   1. Assert a discoverable credential (empty allowCredentials) → credentialId + PRF.
  //   2. Fetch the server blob for that credentialId.
  //      - Found → decrypt with the PRF key, verify the derived address matches
  //        the stored rivet, and restore the ORIGINAL rivet.
  //      - Missing → reuse the SAME passkey to wrap a fresh rivet (no new passkey,
  //        no second prompt); the identity address is new but the credential is not.
  // Throws if the user has no passkey for this RP or cancels — the caller then
  // offers create() for a genuine first registration.
  static async recover(ethers) {
    if (!window.PublicKeyCredential || !navigator.credentials?.get) {
      throw new Error("WebAuthn not available in this browser");
    }
    const { credentialId, prfBytes } = await FidoWallet._prfAssertDiscoverable();
    const blob = await FidoWallet.fetchBlob(credentialId);

    if (blob && blob.ciphertext && blob.iv) {
      const aesKey = await FidoWallet._aesKeyFromPRF(prfBytes, ["decrypt"]);
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ethers.utils.arrayify(blob.iv) },
        aesKey,
        ethers.utils.arrayify(blob.ciphertext),
      );
      const priv = ethers.utils.hexlify(new Uint8Array(plaintext));
      const signingKey = new ethers.utils.SigningKey(priv);
      const address = ethers.utils.computeAddress(signingKey.publicKey);
      if (
        blob.rivetAddress &&
        address.toLowerCase() !== blob.rivetAddress.toLowerCase()
      ) {
        throw new Error(
          "FidoWallet recover: decrypted key does not match the stored rivet address",
        );
      }
      const wallet = new FidoWallet();
      wallet.credentialId = credentialId;
      wallet.address = address;
      wallet.publicKey = signingKey.publicKey;
      wallet.label = blob.label || "FIDO Wallet";
      wallet.createdAt = Date.now();
      wallet.lastUpdated = wallet.createdAt;
      wallet.encryptedPrivateKey = JSON.stringify({
        ciphertext: blob.ciphertext,
        iv: blob.iv,
      });
      wallet._priv = priv; // session cache
      return wallet;
    }

    // Passkey exists but its server blob is gone: reuse the passkey, mint a
    // fresh rivet under it. No NEW passkey, no second biometric prompt.
    return await FidoWallet._wrapNewRivet(ethers, {
      credentialId,
      prfBytes,
      label: "FIDO Wallet",
    });
  }

  // Fetch the stored blob from the epistery server (post-purge recovery).
  // Returns the record ({ ciphertext, iv, rivetAddress, publicKey, label }) or
  // null on failure. _decryptPrivateKey uses only ciphertext/iv; recover() also
  // reads rivetAddress/label — the server returns the full record either way.
  static async fetchBlob(credentialId) {
    try {
      const res = await fetch(
        `${FidoWallet._rootPath()}/fido/blob/${encodeURIComponent(credentialId)}`,
      );
      if (!res.ok) return null;
      const body = await res.json();
      if (!body?.ciphertext || !body?.iv) return null;
      return {
        ciphertext: body.ciphertext,
        iv: body.iv,
        rivetAddress: body.rivetAddress || null,
        publicKey: body.publicKey || null,
        label: body.label || null,
      };
    } catch {
      return null;
    }
  }

  // Decrypts the rivet private key in memory, then caches it for the wallet's
  // session lifetime (this._priv) so a subsequent sign/encrypt/decrypt reuses
  // it without another FIDO ceremony — one Face ID / Touch ID per session, not
  // per operation (the "invisible after unlock" behaviour EpisteryMobileIdentity
  // specifies, matching RivetWallet/Web3Wallet._unlock). Falls back to the
  // server-stored blob if the local copy is missing (the iOS ITP purge recovery
  // path). The cached key is session-only: toJSON never serialises it, and it is
  // discarded when the instance is (wallet switch/reload re-mints via fromJSON).
  async _decryptPrivateKey(ethers) {
    if (this._priv) return this._priv;
    if (!this.credentialId) {
      throw new Error("FidoWallet missing credentialId");
    }

    let blob = this.encryptedPrivateKey
      ? JSON.parse(this.encryptedPrivateKey)
      : null;

    if (!blob) {
      blob = await FidoWallet.fetchBlob(this.credentialId);
      if (!blob) {
        throw new Error(
          "FidoWallet: encrypted blob missing locally and on server",
        );
      }
      this.encryptedPrivateKey = JSON.stringify(blob);
    }

    const prfBytes = await FidoWallet._prfDeriveOnGet(this.credentialId);
    const aesKey = await FidoWallet._aesKeyFromPRF(prfBytes, ["decrypt"]);

    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ethers.utils.arrayify(blob.iv) },
      aesKey,
      ethers.utils.arrayify(blob.ciphertext),
    );

    this._priv = ethers.utils.hexlify(new Uint8Array(plaintext));
    return this._priv;
  }

  async sign(message, ethers) {
    const privateKey = await this._decryptPrivateKey(ethers);
    const signer = new ethers.Wallet(privateKey);
    return await signer.signMessage(message);
  }

  async signTransaction(unsignedTx, ethers) {
    const privateKey = await this._decryptPrivateKey(ethers);
    const signer = new ethers.Wallet(privateKey);
    if (signer.address.toLowerCase() !== this.address.toLowerCase()) {
      throw new Error("Decrypted key does not match FidoWallet address");
    }
    return await signer.signTransaction(unsignedTx);
  }

  // ECDH + AES-GCM peer encryption. Private key is unwrapped by the
  // FIDO authenticator via _decryptPrivateKey, used to derive the shared
  // AES key, then goes out of scope at return — same lifecycle as sign().
  async encryptForPeer(peerPublicKey, plaintextBytes, ethers) {
    const privateKey = await this._decryptPrivateKey(ethers);
    const aesKey = await _deriveAesKeyFromPriv(privateKey, peerPublicKey, ethers);
    return await _aesGcmEncrypt(aesKey, plaintextBytes);
  }

  async decryptFromPeer(peerPublicKey, ciphertextBytes, ivBytes, tagBytes, ethers) {
    const privateKey = await this._decryptPrivateKey(ethers);
    const aesKey = await _deriveAesKeyFromPriv(privateKey, peerPublicKey, ethers);
    return await _aesGcmDecrypt(aesKey, ciphertextBytes, ivBytes, tagBytes);
  }
}

if (typeof window !== "undefined") {
  window.FidoWallet = FidoWallet;
}
