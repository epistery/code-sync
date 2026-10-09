/*
 * Witness - Browser client for Epistery
 *
 * This is the browser-side client that connects to the Epistery server
 * and provides local wallet functionality for signing data
 */

import {
  Wallet,
  Web3Wallet,
  RivetWallet,
  FidoWallet,
} from "./wallet.js?v=11";
import {
  tabId,
  armTab,
  activeWalletId,
  pinWallet,
  unpinWallet,
  installTabHeader,
} from "./tab.js?v=1";
import { keyExchangeMessage, serverResponseMessage } from "./key-exchange-message.mjs";

// Every same-origin request from this tab names this tab, from module load —
// before any code below runs a fetch. Inert until the tab is armed by its first
// key exchange. See tab.js for why the rule lives in one shim.
installTabHeader();

// Global ethers variable - will be loaded dynamically if needed
let ethers;

// Function to ensure ethers is loaded
async function ensureEthers() {
  if (ethers) return ethers;

  if (typeof window !== "undefined" && window.ethers) {
    ethers = window.ethers;
    return ethers;
  }

  // Get rootPath from Witness instance if available
  const rootPath = Witness.instance?.rootPath || "";

  // Dynamically import ethers from the epistery lib endpoint
  try {
    const ethersModule = await import(`${rootPath}/lib/ethers.js`);
    ethers = ethersModule.ethers || ethersModule.default || ethersModule;
    // Make it available globally for future use
    if (typeof window !== "undefined") {
      window.ethers = ethers;
    }
    return ethers;
  } catch (error) {
    console.error("Failed to load ethers.js:", error);
    throw new Error("ethers.js is required but not available");
  }
}

// --- Orphaned-rivet recovery -------------------------------------------------
// A RivetWallet is split across two per-origin stores: the rivet record
// (keyId + AES-encrypted private key) in localStorage["epistery"], and the
// non-extractable AES master key that decrypts it in IndexedDB
// (EpisteryRivets/masterKeys, keyed by keyId). Browsers evict IndexedDB far
// more aggressively than localStorage, so the master key can vanish while the
// rivet record survives. sign() then throws "Master key not found" on every
// connect(), and connect() never self-heals because it only mints a fresh
// rivet when there is NO wallet at all (see `if (!witness.wallet)` below).
//
// reset_master_key() is the manual recovery path: it finds rivet records whose
// master key is missing and removes those records so the next page load mints
// a fresh device key for this origin. It is intentionally NOT called from
// connect() — advise affected users to run reset_master_key() in the console
// until the impact of auto-healing is understood.
//
// Scope note: IndexedDB and localStorage are siloed per ORIGIN (scheme + host
// + port), stricter than cookies. This only ever touches the current origin;
// it cannot affect any other site. The cost is a NEW device address for THIS
// origin — anything bound to the old address here (follows, previously-signed
// messages) will not carry over.
async function reset_master_key({ confirm = true } = {}) {
  const raw = localStorage.getItem("epistery");
  if (!raw) {
    console.log(
      "[reset_master_key] No epistery storage on this origin — nothing to reset. Reload to mint a fresh device key.",
    );
    return { removed: 0, healthy: 0 };
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    console.warn(
      "[reset_master_key] epistery storage is corrupt JSON; clearing it.",
      e,
    );
    localStorage.removeItem("epistery");
    setTimeout(() => location.reload(), 250);
    return { removed: -1, healthy: 0 };
  }

  // Support both the legacy single-wallet shape and the multi-wallet shape.
  const isMulti = Array.isArray(data.wallets);
  const entries = isMulti
    ? data.wallets
    : data.wallet
      ? [{ id: "legacy", wallet: data.wallet }]
      : [];

  const orphaned = [];
  let healthy = 0;
  for (const entry of entries) {
    const wal = entry.wallet || entry;
    if (!wal || wal.source !== "rivet") continue;
    const masterKey = wal.keyId
      ? await RivetWallet.getMasterKey(wal.keyId)
      : null;
    if (masterKey) {
      healthy++;
    } else {
      orphaned.push({ id: entry.id, keyId: wal.keyId, address: wal.address });
    }
  }

  if (orphaned.length === 0) {
    console.log(
      `[reset_master_key] No orphaned rivets found (${healthy} healthy). Nothing to do.`,
    );
    return { removed: 0, healthy };
  }

  console.log(
    `[reset_master_key] Found ${orphaned.length} orphaned rivet(s) — master key missing from IndexedDB:`,
    orphaned,
  );

  if (confirm && typeof window?.confirm === "function") {
    const ok = window.confirm(
      `Epistery: ${orphaned.length} device key(s) on ${location.host} can't be unlocked — ` +
        `the browser evicted their master key. Reset will mint a NEW device address for this site only. Continue?`,
    );
    if (!ok) {
      console.log("[reset_master_key] Cancelled — no changes made.");
      return { removed: 0, healthy, cancelled: true };
    }
  }

  if (isMulti) {
    const orphanIds = new Set(orphaned.map((o) => o.id));
    data.wallets = data.wallets.filter((w) => !orphanIds.has(w.id));
    if (orphanIds.has(data.defaultWalletId)) {
      data.defaultWalletId = data.wallets[0]?.id || null;
    }
    // This tab's pin outranks the device default on the next load, so an
    // orphaned pin would undo the whole recovery. Drop it and let the tab fall
    // back to the default we just repointed.
    if (orphanIds.has(activeWalletId())) unpinWallet();
    localStorage.setItem("epistery", JSON.stringify(data));
  } else {
    // Legacy shape: the single wallet is the orphan.
    localStorage.removeItem("epistery");
    unpinWallet();
  }

  console.log(
    `[reset_master_key] Removed ${orphaned.length} orphaned rivet(s) (${healthy} healthy kept). Reloading to mint a fresh device key…`,
  );
  setTimeout(() => location.reload(), 250);
  return { removed: orphaned.length, healthy };
}

if (typeof window !== "undefined") {
  window.reset_master_key = reset_master_key;
}

export default class Witness {
  constructor(rootPath) {
    if (Witness.instance) return Witness.instance;
    Witness.instance = this;
    this.wallet = null;
    this.server = null;
    // Normalize rootPath - remove trailing slash, default to '..'
    this.rootPath = (rootPath || "..").replace(/\/$/, "");
    return this;
  }

  save() {
    const storageData = this.loadStorageData();

    // If current wallet exists, update or add it to the wallets array
    if (this.wallet) {
      const walletData = {
        id: this.wallet.id || this.generateWalletId(this.wallet.source),
        wallet: this.wallet.toJSON(),
        label:
          this.wallet.label ||
          (this.wallet.source === "web3" ? "Web3 Wallet" : "Browser Wallet"),
        createdAt: this.wallet.createdAt || Date.now(),
        lastUsed: Date.now(),
      };

      // Store the ID back on the wallet object
      this.wallet.id = walletData.id;
      this.wallet.label = walletData.label;
      this.wallet.createdAt = walletData.createdAt;

      // Update or add wallet in the array
      const existingIndex = storageData.wallets.findIndex(
        (w) => w.id === walletData.id,
      );
      if (existingIndex >= 0) {
        storageData.wallets[existingIndex] = walletData;
      } else {
        storageData.wallets.push(walletData);
      }

      // Set as default if no default exists
      if (!storageData.defaultWalletId) {
        storageData.defaultWalletId = walletData.id;
      }
    }

    storageData.server = this.server;

    localStorage.setItem("epistery", JSON.stringify(storageData));
  }

  loadStorageData() {
    const data = localStorage.getItem("epistery");
    if (!data) {
      return { wallets: [], defaultWalletId: null, server: null };
    }

    try {
      const parsed = JSON.parse(data);

      // Migrate old single-wallet format to new multi-wallet format
      if (parsed.wallet && !parsed.wallets) {
        const migratedWalletId = this.generateWalletId(parsed.wallet.source);
        return {
          wallets: [
            {
              id: migratedWalletId,
              wallet: parsed.wallet,
              label:
                parsed.wallet.source === "web3"
                  ? "Web3 Wallet"
                  : "Browser Wallet",
              createdAt: Date.now(),
              lastUsed: Date.now(),
            },
          ],
          defaultWalletId: migratedWalletId,
          server: parsed.server,
        };
      }

      return {
        wallets: parsed.wallets || [],
        defaultWalletId: parsed.defaultWalletId || null,
        server: parsed.server || null,
      };
    } catch (error) {
      console.error("Failed to parse epistery data:", error);
      return { wallets: [], defaultWalletId: null, server: null };
    }
  }

  async load() {
    const storageData = this.loadStorageData();

    this.server = storageData.server;

    // Purge legacy/unsupported wallets. Only the three rivet types (web3,
    // browser "rivet", fido) may engage an epistery site. The pre-2.0 plaintext
    // "local" browser wallet is NOT a rivet; scrub it from storage so no exposed
    // private key is left behind (hygiene — the security is the rivet, not
    // hiding this). A single legacy entry must never abort the load of the rest.
    const RIVET_SOURCES = new Set(["web3", "rivet", "fido"]);
    const before = storageData.wallets.length;
    storageData.wallets = storageData.wallets.filter((w) =>
      RIVET_SOURCES.has((w.wallet || w)?.source),
    );
    const purged = before - storageData.wallets.length;
    if (
      purged > 0 &&
      !storageData.wallets.some((w) => w.id === storageData.defaultWalletId)
    ) {
      storageData.defaultWalletId = storageData.wallets[0]?.id || null;
    }

    // Persist when we migrated the old single-wallet format OR purged a legacy
    // wallet — either way the on-disk shape must reflect what we just normalized.
    const currentData = localStorage.getItem("epistery");
    if (currentData) {
      const parsed = JSON.parse(currentData);
      const migrated =
        parsed.wallet && !parsed.wallets && storageData.wallets.length > 0;
      if (migrated || purged > 0) {
        if (purged > 0) {
          console.warn(
            `[epistery] Purged ${purged} legacy non-rivet wallet(s) from storage.`,
          );
        }
        localStorage.setItem("epistery", JSON.stringify(storageData));
      }
    }

    // Which rivet is THIS TAB being? The tab's own pin wins; the device default
    // is what an unpinned (brand new) tab starts as. A pin naming a wallet this
    // origin no longer holds is stale — drop it and fall back, rather than
    // leaving the tab with no identity at all.
    let activeId = activeWalletId();
    if (activeId && !storageData.wallets.some((w) => w.id === activeId)) {
      unpinWallet();
      activeId = null;
    }
    activeId = activeId || storageData.defaultWalletId;

    // Load the active wallet if it exists. fromJSON returns null for an
    // unsupported source — skip rather than crash.
    if (activeId && ethers) {
      const walletData = storageData.wallets.find((w) => w.id === activeId);
      if (walletData) {
        const wallet = await Wallet.fromJSON(walletData.wallet, ethers);
        if (wallet) {
          this.wallet = wallet;
          this.wallet.id = walletData.id;
          this.wallet.label = walletData.label;
          this.wallet.createdAt = walletData.createdAt;
          // Pin what we resolved. A tab holds its rivet from the moment it
          // loads, so a switch in ANOTHER tab (which moves defaultWalletId)
          // can never change what this tab is on its next reload.
          pinWallet(walletData.id);
        }
      }
    }
  }

  generateWalletId(source) {
    let prefix = "browser-wallet"; // legacy default
    if (source === "web3") {
      prefix = "web3-wallet";
    } else if (source === "rivet") {
      prefix = "rivet";
    }
    return (
      prefix + "-" + Date.now() + "-" + Math.random().toString(36).substr(2, 9)
    );
  }

  static async connect(options = {}) {
    let witness = new Witness(options.rootPath);

    try {
      // Ensure ethers is loaded first
      ethers = await ensureEthers();

      // Load existing data (now that ethers is available)
      await witness.load();

      // Get server info to check chain compatibility
      await witness.fetchServerInfo();

      // Initialize wallet if needed
      if (!witness.wallet) {
        await witness.initialize();
      }

      // Verify chain compatibility and switch if needed
      await witness.ensureChainCompatibility();

      // Establish mutual proof of identity
      if (!options.skipKeyExchange) {
        await witness.performKeyExchange();
      }
    } catch (e) {
      console.error("Failed to connect to Epistery server:", e);
      // For unclaimed domains, wallet discovery might succeed even if key exchange fails
      if (!options.skipKeyExchange) {
        throw e;
      }
    }

    return witness;
  }

  async initialize() {
    try {
      // Try RivetWallet first (non-extractable, invisible, zero friction)
      this.wallet = await RivetWallet.create(ethers);

      // Only try Web3 if user explicitly requests (not automatic).

      if (this.wallet) {
        console.log(
          `Wallet initialized: ${this.wallet.source} (${this.wallet.address})`,
        );
        this.save();
        pinWallet(this.wallet.id);
      } else {
        throw new Error("Failed to create rivet wallet");
      }
    } catch (e) {
      console.error("Failed to initialize wallet:", e);
    }
  }

  async fetchServerInfo() {
    try {
      const response = await fetch(this.rootPath||'/', {
        headers: { Accept: "application/json" },
      });
      if (response.ok) {
        const serverInfo = await response.json();
        this.serverInfo = serverInfo.server;
      } else {
        throw new Error("Failed to fetch server info");
      }
    } catch (e) {
      console.error("Failed to fetch server info:", e);
    }
  }

  async ensureChainCompatibility() {
    if (!this.wallet || this.wallet.source !== "web3" || !this.serverInfo) {
      return;
    }
    // Locked-rivet web3 wallets restore lazily — no provider until first
    // plugin use. Chain compatibility only matters when the plugin itself
    // sends a tx (legacy path), and that path switches chains at tx time.
    if (!this.wallet.provider || typeof this.wallet.provider.getNetwork !== "function") {
      return;
    }

    try {
      const targetChainId = this.serverInfo.chainId;
      const targetRpc = this.serverInfo.rpc;

      // Get current chain ID
      const currentNetwork = await this.wallet.provider.getNetwork();

      // Parse server chain ID (remove comma if present)
      const expectedChainId = parseInt(
        targetChainId.toString().replace(",", ""),
      );

      if (currentNetwork.chainId !== expectedChainId) {
        await this.requestChainSwitch(
          expectedChainId,
          targetRpc,
          this.serverInfo.provider,
        );
      }
    } catch (e) {
      console.warn("Chain compatibility check failed:", e);
    }
  }

  async requestChainSwitch(chainId, rpcUrl, networkName) {
    if (!window.ethereum) {
      throw new Error("No Web3 provider available for chain switching");
    }

    try {
      // First, try to switch to the chain
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: `0x${chainId.toString(16)}` }],
      });
    } catch (switchError) {
      // If the chain hasn't been added to MetaMask, add it
      if (switchError.code === 4902) {
        try {
          // Build nativeCurrency from serverInfo with sensible defaults
          const nativeCurrency = this.serverInfo?.nativeCurrency || {
            name: "ETH",
            symbol: "ETH",
            decimals: 18,
          };

          await window.ethereum.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: `0x${chainId.toString(16)}`,
                chainName: networkName || `Chain ${chainId}`,
                rpcUrls: [rpcUrl],
                nativeCurrency: nativeCurrency,
              },
            ],
          });
        } catch (addError) {
          console.error("Failed to add chain:", addError);
          throw addError;
        }
      } else {
        console.error("Failed to switch chain:", switchError);
        throw switchError;
      }
    }

    // Recreate the provider connection after chain switch
    if (this.wallet && this.wallet.source === "web3") {
      this.wallet.provider = new ethers.providers.Web3Provider(window.ethereum);
      this.wallet.signer = this.wallet.provider.getSigner();
    }
  }

  generateChallenge() {
    // Generate a random 32-byte challenge for key exchange
    return ethers.utils.hexlify(ethers.utils.randomBytes(32));
  }

  async performKeyExchange() {
    try {
      if (!this.wallet) {
        throw new Error("No wallet available for key exchange");
      }

      // Claim this tab's session slot BEFORE the first request below, so both
      // the /connect probe and the handshake itself carry X-Epistery-Tab and
      // read/write this tab's slot rather than the shared default. Arming is
      // what turns tab isolation on for this tab; see tab.js.
      armTab();

      // Two facts the wallet states; one of them carries a proof.
      //   signerAddress    — the rivet we sign with (proven by `signature`).
      //   contractAddress  — the IdentityContract we CLAIM to speak for, or
      //                      null. Server verifies via on-chain isAuthorized.
      // identityAddress is the derived canonical (contract || signer); we
      // only use it locally to decide whether the cookie already names us.
      const { signerAddress, contractAddress, identityAddress, publicKey } =
        this.wallet;

      // Skip re-exchange only when the cookie already names our CURRENT
      // identity. Both sides derive identityAddress from the same two facts,
      // so comparing identity-to-identity is correct by construction — no
      // ambiguity, no "did you mean signer or contract?" reasoning.
      try {
        const check = await fetch(`${this.rootPath}/connect`, {
          credentials: "include",
        });
        if (check.ok) {
          const session = await check.json();
          if (
            session.identityAddress &&
            session.identityAddress.toLowerCase() ===
              identityAddress.toLowerCase()
          ) {
            return;
          }
        }
      } catch (e) {
        // No valid session, proceed with key exchange
      }

      // Sign over signerAddress — what the server's recovery proves.
      const challenge = this.generateChallenge();
      const message = keyExchangeMessage({ address: signerAddress, challenge });
      const signature = await this.wallet.sign(message, ethers);

      const keyExchangeData = {
        signerAddress,
        signerPublicKey: publicKey,
        contractAddress: contractAddress || null, // present in every request; null when unbound
        challenge,
        message,
        signature,
        walletSource: this.wallet.source,
      };

      const response = await fetch(`${this.rootPath}/connect`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(keyExchangeData),
      });

      if (response.ok) {
        const serverResponse = await response.json();

        // Verify server's identity by checking signature
        if (this.verifyServerIdentity(serverResponse)) {
          this.server = {
            address: serverResponse.serverAddress,
            publicKey: serverResponse.serverPublicKey,
            services: serverResponse.services,
            challenge: serverResponse.challenge,
            signature: serverResponse.signature,
            identified: true,
            provider: this.serverInfo?.provider,
            chainId: this.serverInfo?.chainId,
            rpc: this.serverInfo?.rpc,
            rpcProxy: this.serverInfo?.rpcProxy,
            nativeCurrency: this.serverInfo?.nativeCurrency,
            // The domain's countersignature on THIS device key — {rivet, domain,
            // ts} signed by the domain's own wallet. Kept because it is the only
            // part of this handshake a THIRD party can check: the rivet's own
            // signature binds an event to the device, and this binds the device to
            // the domain. save() persists `server` wholesale, so it survives a
            // reload and can be presented later. Null against a server that does
            // not issue one, which is how an older host reads — absent, not
            // invalid. See client/origin-certificate.mjs.
            certificate: serverResponse.certificate || null,
          };

          this.save();
          console.log("Key exchange completed successfully");
          console.log("Server address:", this.server.address);
        } else {
          throw new Error("Server identity verification failed");
        }
      } else {
        const errorResponse = await response.json();
        throw new Error(
          `Key exchange failed with status: ${response.status} - ${errorResponse.error || "Unknown error"}`,
        );
      }
    } catch (e) {
      console.error("Key exchange failed:", e);
      throw e;
    }
  }

  verifyServerIdentity(serverResponse) {
    try {
      // The message the host signed — the wire's one definition.
      const expectedMessage = serverResponseMessage({ address: serverResponse.serverAddress, challenge: serverResponse.challenge });
      const recoveredAddress = ethers.utils.verifyMessage(expectedMessage, serverResponse.signature);
      return recoveredAddress.toLowerCase() === String(serverResponse.serverAddress).toLowerCase();
    } catch (e) {
      console.error("Server identity verification error:", e);
      return false;
    }
  }

  // Wallet management methods for multi-wallet support

  getWallets() {
    const storageData = this.loadStorageData();
    const active = activeWalletId() || storageData.defaultWalletId;
    return {
      wallets: storageData.wallets.map((w) => {
        // Derive the three-fact shape from RAW storage so it's correct even
        // for legacy records that fromJSON hasn't un-flipped yet (getWallets
        // reads storage directly, not via fromJSON). signerAddress is always
        // the rivet; identityAddress is the contract when bound.
        const rivet = w.wallet.rivetAddress || w.wallet.address;
        const contract = w.wallet.contractAddress || null;
        return {
          id: w.id,
          // `address` kept for back-compat; may be the contract on an
          // un-migrated legacy record. Render rivetAddress/signerAddress.
          address: w.wallet.address,
          rivetAddress: rivet,
          signerAddress: rivet,
          contractAddress: contract,
          identityAddress: contract || rivet,
          source: w.wallet.source,
          label: w.label,
          createdAt: w.createdAt,
          lastUsed: w.lastUsed,
          // TWO different facts, deliberately not merged: isDefault is the
          // DEVICE default (what a new tab starts as), isActive is what THIS
          // TAB is being right now. They differ whenever a tab has switched.
          isDefault: w.id === storageData.defaultWalletId,
          isActive: w.id === active,
        };
      }),
      defaultWalletId: storageData.defaultWalletId,
      activeWalletId: active,
      tabId: tabId(),
    };
  }

  async addWeb3Wallet(label = null) {
    await ensureEthers();
    const newWallet = await Web3Wallet.create(ethers);

    if (!newWallet) {
      throw new Error(
        "Failed to connect Web3 wallet. User may have cancelled or no Web3 provider available.",
      );
    }

    newWallet.label = label || "Web3 Wallet";

    // Temporarily set as active wallet to save it
    const previousWallet = this.wallet;
    this.wallet = newWallet;
    this.save();

    // Restore previous wallet if there was one
    if (previousWallet) {
      this.wallet = previousWallet;
    }

    return {
      id: newWallet.id,
      address: newWallet.address,
      source: newWallet.source,
      label: newWallet.label,
    };
  }


  // Add a Browser Wallet: a localStorage rivet whose secp256k1 key is wrapped by
  // a non-extractable WebCrypto master key (the older exposed-key version is gone
  // — this is the only "browser wallet"). All wallet kinds (Browser/Fido/Web3)
  // are rivets — device-locked signing keys. Lets one device hold multiple
  // independent, non-linked identities (one key, one identity) the way
  // Ledger/Trezor/MetaMask do.
  async addBrowserWallet(label = null) {
    await ensureEthers();
    const newWallet = await RivetWallet.create(ethers);

    if (!newWallet) {
      throw new Error("Failed to create wallet");
    }

    newWallet.label = label || "Browser Wallet";

    // Temporarily set as active wallet to save it
    const previousWallet = this.wallet;
    this.wallet = newWallet;
    this.save();

    // Restore previous wallet if there was one
    if (previousWallet) {
      this.wallet = previousWallet;
    }

    return {
      id: newWallet.id,
      address: newWallet.address,
      source: newWallet.source,
      label: newWallet.label,
    };
  }

  async addFidoWallet(label = null) {
    await ensureEthers();
    // Exclude passkeys this device already knows about so create() can't mint a
    // duplicate for a credential we still hold (the offer re-firing while storage
    // is intact). Post-purge there are no local ids — recoverFidoWallet covers that.
    const excludeCredentials = this.loadStorageData()
      .wallets.map((w) => w.wallet || w)
      .filter((w) => w?.source === "fido" && w?.credentialId)
      .map((w) => w.credentialId);

    const newWallet = await FidoWallet.create(ethers, {
      label: label || "FIDO Wallet",
      excludeCredentials,
    });

    if (!newWallet) {
      throw new Error("Failed to create FIDO wallet");
    }

    // Temporarily set as active wallet to save it
    const previousWallet = this.wallet;
    this.wallet = newWallet;
    this.save();

    // Restore previous wallet if there was one
    if (previousWallet) {
      this.wallet = previousWallet;
    }

    return {
      id: newWallet.id,
      address: newWallet.address,
      source: newWallet.source,
      label: newWallet.label,
    };
  }

  // Recover an existing passkey identity (post-ITP-purge, or a new browser)
  // instead of minting a new one. Unlike addFidoWallet, this installs the
  // recovered wallet as the LIVE active + default wallet directly — keeping the
  // in-memory _priv the recover ceremony just cached, so the caller's immediate
  // performKeyExchange signs without a second biometric prompt. (Going through
  // setDefaultWallet would rebuild the wallet via fromJSON and drop that cache.)
  // Returns the wallet summary, or null if no passkey was found / the user
  // cancelled — the caller then falls back to addFidoWallet for a first-timer.
  async recoverFidoWallet() {
    await ensureEthers();
    const recovered = await FidoWallet.recover(ethers);
    if (!recovered) return null;

    this.wallet = recovered; // live instance — retains _priv
    this.save(); // assigns id, appends to wallets[]

    const storageData = this.loadStorageData();
    storageData.defaultWalletId = this.wallet.id;
    storageData.server = this.server;
    localStorage.setItem("epistery", JSON.stringify(storageData));
    pinWallet(this.wallet.id);

    return {
      id: this.wallet.id,
      address: this.wallet.address,
      source: this.wallet.source,
      label: this.wallet.label,
    };
  }

  // --- Paper (BIP39) backup rivets -------------------------------------------
  // A paper rivet is the offline backup signer: a BIP39 phrase the human holds,
  // authorized as a signer on the identity, with no agency on any device until
  // reconstructed. These three are the witness façade over RivetWallet's paper
  // helpers; the console composes them with its existing on-chain addRivet (for
  // Add backup) and rivetContracts→adopt (for Recover).

  // Generate a fresh 12-word backup phrase. The caller derives its address
  // (paperRivetAddress), authorizes that address as a signer, then shows the
  // phrase once — it is the only copy.
  async generatePaperPhrase() {
    await ensureEthers();
    return RivetWallet.generatePaperPhrase(ethers);
  }

  // Resolve a phrase (generated or user-entered) to the rivet address/publicKey
  // it authorizes. No wallet is built or stored — Add backup only needs the
  // address to put on-chain. Throws on an invalid phrase.
  async paperRivetAddress(phrase) {
    await ensureEthers();
    return RivetWallet.paperAddressFromPhrase(phrase, ethers);
  }

  // Recover an identity from its paper backup phrase on a fresh device. The
  // phrase re-derives the rivet, which is re-homed as a DURABLE non-extractable
  // browser rivet here (RivetWallet custody) and installed as the LIVE active +
  // default wallet — mirroring recoverFidoWallet (setDefaultWallet would rebuild
  // via fromJSON; installing the live instance keeps this one canonical). The
  // caller then runs performKeyExchange and the existing rivetContracts→adopt
  // discovery to re-root on the IdentityContract this signer is authorized on.
  // Throws on an invalid phrase.
  async recoverPaperIdentity(phrase) {
    await ensureEthers();
    const recovered = await RivetWallet.fromPhrase(phrase, ethers, "Recovered Wallet");

    this.wallet = recovered; // live instance
    this.save(); // assigns id, appends to wallets[]

    const storageData = this.loadStorageData();
    storageData.defaultWalletId = this.wallet.id;
    storageData.server = this.server;
    localStorage.setItem("epistery", JSON.stringify(storageData));
    pinWallet(this.wallet.id);

    return {
      id: this.wallet.id,
      address: this.wallet.address,
      source: this.wallet.source,
      label: this.wallet.label,
    };
  }

  // Become this rivet: in THIS TAB now, and as the device default for tabs
  // opened from here on. Other open tabs keep the rivet they loaded with — their
  // pin already names it, so moving defaultWalletId cannot reach them. The
  // caller must follow with performKeyExchange() to move the server session in
  // this tab's slot too; switching the client alone would leave the two halves
  // disagreeing.
  async setActiveWallet(walletId) {
    const storageData = this.loadStorageData();
    const walletData = storageData.wallets.find((w) => w.id === walletId);

    if (!walletData) {
      throw new Error(`Wallet with ID ${walletId} not found`);
    }

    await ensureEthers();

    // Load the wallet
    this.wallet = await Wallet.fromJSON(walletData.wallet, ethers);
    this.wallet.id = walletData.id;
    this.wallet.label = walletData.label;
    this.wallet.createdAt = walletData.createdAt;

    // This tab is this wallet, stated before anything else — a failure after
    // here leaves the tab pointing at the wallet it actually loaded.
    pinWallet(walletId);

    // And it becomes the device default: what the next new tab starts as.
    storageData.defaultWalletId = walletId;
    storageData.wallets = storageData.wallets.map((w) => {
      if (w.id === walletId) {
        w.lastUsed = Date.now();
      }
      return w;
    });

    localStorage.setItem("epistery", JSON.stringify(storageData));

    console.log(
      `Switched to wallet: ${this.wallet.source} (${this.wallet.address})`,
    );

    return {
      id: this.wallet.id,
      address: this.wallet.address,
      source: this.wallet.source,
      label: this.wallet.label,
    };
  }

  // Pre-tab name for setActiveWallet, kept so existing consumers keep working.
  async setDefaultWallet(walletId) {
    return this.setActiveWallet(walletId);
  }

  removeWallet(walletId) {
    const storageData = this.loadStorageData();

    // Don't allow removing the default wallet if it's the only one
    if (storageData.wallets.length === 1) {
      throw new Error("Cannot remove the only wallet");
    }

    // Don't allow removing the default wallet without switching first
    if (storageData.defaultWalletId === walletId) {
      throw new Error(
        "Cannot remove default wallet. Switch to another wallet first.",
      );
    }

    // Nor the one THIS TAB is being — the tab's pin is as real a claim on a
    // wallet as the device default is, and removing it would leave this tab
    // signing as something it never chose.
    if (activeWalletId() === walletId) {
      throw new Error(
        "Cannot remove the wallet this tab is using. Switch to another wallet first.",
      );
    }

    const walletIndex = storageData.wallets.findIndex((w) => w.id === walletId);
    if (walletIndex === -1) {
      throw new Error(`Wallet with ID ${walletId} not found`);
    }

    storageData.wallets.splice(walletIndex, 1);
    localStorage.setItem("epistery", JSON.stringify(storageData));

    return true;
  }

  updateWalletLabel(walletId, newLabel) {
    const storageData = this.loadStorageData();
    const walletData = storageData.wallets.find((w) => w.id === walletId);

    if (!walletData) {
      throw new Error(`Wallet with ID ${walletId} not found`);
    }

    walletData.label = newLabel;

    // If this is the current wallet, update it too
    if (this.wallet && this.wallet.id === walletId) {
      this.wallet.label = newLabel;
    }

    localStorage.setItem("epistery", JSON.stringify(storageData));

    return true;
  }

  getStatus() {
    return {
      client: this.wallet
        ? {
            address: this.wallet.rivetAddress || this.wallet.address,
            publicKey: this.wallet.publicKey,
            source: this.wallet.source,
          }
        : null,
      server: this.server,
      connected: !!(this.wallet && this.server),
    };
  }
}
