import { ethers, Wallet } from 'ethers';
import { Config } from './Config';
import { DomainConfig, ProviderConfig, KeyExchangeRequest, KeyExchangeResponse } from './types';
import { sharedSecretOf } from './PeerCapability';
import { defaultChain, providerConfigFor } from '../chains';
import { createHash, randomBytes } from 'crypto';
import { loadClientModule } from './clientModule';

/**
 * The request a bot signature authorises. Either `url`, or both `uri` and
 * `aud`, must be supplied — a bot signature that names no request is a bearer
 * token, which is the thing this shape exists to prevent.
 */
export interface BotAuthRequest {
  method?: string;
  uri?: string;
  aud?: string;
  url?: string;
  body?: string | Buffer | null;
}

/**
 * CliWallet - Manages wallet operations for CLI/bot contexts
 *
 * Uses Epistery's domain configuration system:
 * - Domain configs stored in ~/.epistery/{domain}/config.ini
 * - Each domain has its own wallet (like server-side)
 * - Default domain configurable in ~/.epistery/config.ini [cli] section
 * - Automatic wallet creation on initialize
 *
 * This matches the server-side model where each domain has a wallet,
 * making CLI usage consistent with server architecture.
 */

export interface SessionInfo {
  domain: string;
  cookie: string;
  authenticated: boolean;
  timestamp: string;
}

export class CliWallet {
  private config: Config;
  private domainName: string;
  private domainConfig: DomainConfig;
  private wallet: Wallet;
  public address: string;
  public publicKey: string;

  private constructor(config: Config, domainName: string, domainConfig: DomainConfig, wallet: Wallet) {
    this.config = config;
    this.domainName = domainName.toLowerCase();
    this.domainConfig = domainConfig;
    this.wallet = wallet;
    this.address = wallet.address;
    this.publicKey = wallet.publicKey;
  }

  /**
   * Get the default domain from config.ini [cli] section
   */
  static async getDefaultDomain(): Promise<string> {
    const config = new Config();
    await config.setPath('/');
    return (config.data as any).cli?.default_domain || 'localhost';
  }

  /**
   * Set the default domain in config.ini [cli] section.
   *
   * Loads the root config first so the rest of it ([profile], [default.provider],
   * …) is preserved on save. (Before the async migration, Config did not
   * auto-load on construction, so this wrote {cli:…} over the whole root file.)
   */
  static async setDefaultDomain(domain: string): Promise<void> {
    const config = new Config();
    await config.setPath('/');
    if (!(config.data as any).cli) {
      (config.data as any).cli = {};
    }
    (config.data as any).cli.default_domain = domain;
    await config.save();
  }

  /**
   * Initialize a new domain with wallet
   * Creates ~/.epistery/{domain}/config.ini with new wallet
   */
  static async initialize(domain: string, provider?: ProviderConfig): Promise<CliWallet> {
    const config = new Config();

    // Check if domain already exists
    await config.setPath(domain);
    if (config.data.wallet) {
      throw new Error(`Domain '${domain}' already initialized. Use load() to access it.`);
    }

    // Create new wallet
    const ethersWallet = ethers.Wallet.createRandom();

    // Chain comes from the caller (epistery initialize --chain) or, failing
    // that, from the configured default chain (registry: root [default]
    // defaultChainId / [default.provider], else Polygon mainnet).
    const providerConfig = provider
      ? providerConfigFor(provider)
      : providerConfigFor(await defaultChain());

    // Create domain config
    await config.setPath(`/${domain}`);
    config.data = {
      domain: domain,
      wallet: {
        address: ethersWallet.address,
        mnemonic: ethersWallet.mnemonic?.phrase || '',
        publicKey: ethersWallet.publicKey,
        privateKey: ethersWallet.privateKey
      },
      provider: providerConfig
    };
    await config.save();

    console.log(`Initialized domain: ${domain}`);
    console.log(`Address: ${ethersWallet.address}`);
    console.log(`Provider: ${providerConfig.name}`);

    return new CliWallet(config, domain, config.data, ethersWallet);
  }

  /**
   * Point an already-initialized domain at a different chain.
   *
   * Only the domain's [provider] block changes — the wallet (and therefore the
   * address) is chain-agnostic and is left exactly as it is. Returns the
   * previous provider config so callers can report the change.
   */
  static async setChain(domain: string, provider: ProviderConfig): Promise<ProviderConfig | undefined> {
    const config = new Config();
    await config.setPath(`/${domain}`);

    if (!config.data.wallet) {
      throw new Error(
        `Domain '${domain}' not found or has no wallet. ` +
        `Initialize with: epistery initialize ${domain}`
      );
    }

    const previous: ProviderConfig | undefined = config.data.provider;
    config.data.provider = providerConfigFor(provider);
    await config.save();

    return previous;
  }

  /**
   * Load domain wallet from config
   * Throws if domain doesn't exist - use initialize() first
   */
  static async load(domain?: string): Promise<CliWallet> {
    const config = new Config();
    const domainName = domain || await CliWallet.getDefaultDomain();

    await config.setPath(`/${domainName}`);

    if (!config.data.wallet) {
      throw new Error(
        `Domain '${domainName}' not found or has no wallet. ` +
        `Initialize with: epistery initialize ${domainName}`
      );
    }

    // Reconstruct wallet from config
    let ethersWallet: Wallet;
    if (config.data.wallet.mnemonic) {
      ethersWallet = ethers.Wallet.fromMnemonic(config.data.wallet.mnemonic);
    } else if (config.data.wallet.privateKey) {
      ethersWallet = new ethers.Wallet(config.data.wallet.privateKey);
    } else {
      throw new Error(`Domain '${domainName}' wallet has no mnemonic or privateKey`);
    }

    return new CliWallet(config, domainName, config.data, ethersWallet);
  }

  /**
   * Get domain name
   */
  getDomain(): string {
    return this.domainName;
  }

  /**
   * Get provider info
   */
  getProvider() {
    return this.domainConfig.provider;
  }

  /**
   * Sign a message
   */
  async sign(message: string): Promise<string> {
    return await this.wallet.signMessage(message);
  }

  // ── member capability surface (PeerCapable) ─────────────────────────────
  // What a session member needs from its rivet, and all it gets: sign, and the
  // raw ECDH shared secret for the TreeKEM leaf-decap seam. The key itself never
  // leaves this object, which is the seam where a hardware-held key replaces the
  // plaintext one in config.ini behind the same members.

  readonly canPeerEncrypt = true;

  /** ethers-Signer-shaped alias of sign(), for member code (storage, inbox,
   *  group commits) that takes a wallet. */
  async signMessage(message: string): Promise<string> {
    return this.sign(message);
  }

  /** Raw ECDH shared secret (32-byte X) with a peer's uncompressed secp256k1
   *  public key — the value the TreeKEM key schedule consumes. */
  async computeSharedSecret(peerPublicKey: string, _ethers?: unknown): Promise<Uint8Array> {
    return sharedSecretOf(this.wallet, peerPublicKey);
  }

  /**
   * Perform key exchange with an Epistery server
   * Automatically saves session cookie to domain config
   */
  async performKeyExchange(serverUrl: string): Promise<KeyExchangeResponse> {
    // Where the host mounted epistery is the host's to say: its well-known
    // location (RFC 8615) answers wherever the routes live and names the
    // handshake. A host that answers nothing there is not an epistery host.
    const baseUrl = serverUrl.replace(/\/$/, '');
    const connectUrl = await CliWallet.discoverConnect(baseUrl);

    // Generate challenge for key exchange
    const challenge = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const { keyExchangeMessage, serverResponseMessage } = await loadClientModule('key-exchange-message.mjs');
    const message = keyExchangeMessage({ address: this.address, challenge });

    // Sign the message
    const signature = await this.sign(message);

    // Prepare key exchange request. The CLI never claims a contract via
    // session cookie today (CLI is bot-auth-first), so contractAddress is
    // null; the server treats it as a signer-only session.
    const requestData: KeyExchangeRequest = {
      signerAddress: this.address,
      signerPublicKey: this.publicKey,
      contractAddress: null,
      challenge: challenge,
      message: message,
      signature: signature,
      walletSource: 'server'
    };

    // Perform key exchange
    const response = await fetch(connectUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestData)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Key exchange failed: ${response.status} - ${errorText}`);
    }

    const serverResponse = await response.json() as KeyExchangeResponse;

    // Verify server's identity
    const expectedMessage = serverResponseMessage({ address: serverResponse.serverAddress, challenge: serverResponse.challenge });
    const recoveredAddress = ethers.utils.verifyMessage(expectedMessage, serverResponse.signature);

    if (recoveredAddress.toLowerCase() !== serverResponse.serverAddress.toLowerCase()) {
      throw new Error('Server identity verification failed');
    }

    // Extract and save session cookie if present
    const cookies = response.headers.get('set-cookie');
    if (cookies) {
      const sessionMatch = cookies.match(/_epistery=([^;]+)/);
      if (sessionMatch) {
        const sessionToken = sessionMatch[1];

        // Save session to domain config
        await this.saveSession({
          domain: serverUrl,
          cookie: sessionToken,
          authenticated: serverResponse.authenticated || false,
          timestamp: new Date().toISOString()
        });
      }
    }

    return serverResponse;
  }

  /** The host's handshake URL, from its well-known discovery answer. */
  static async discoverConnect(baseUrl: string): Promise<string> {
    const wellKnown = `${baseUrl}/.well-known/epistery`;
    let answer: any;
    try {
      const r = await fetch(wellKnown, { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      answer = await r.json();
    } catch (e: any) {
      throw new Error(`${baseUrl} does not answer at ${wellKnown} (${e.message}) — not an epistery host, or not reachable`);
    }
    if (typeof answer?.epistery?.connect === 'string') return `${baseUrl}${answer.epistery.connect}`;
    // A host from before discovery mounted at the well-known path itself.
    return `${wellKnown}/connect`;
  }

  /**
   * The saved session for a server URL, or null when there is none (or the
   * file is not a session). Sessions are files of the wallet's domain config —
   * read through Config, wherever that config lives.
   */
  async getSession(serverUrl: string): Promise<SessionInfo | null> {
    try {
      const data = await this.config.readFile(CliWallet.sessionFileName(serverUrl));
      return JSON.parse(data.toString('utf8')) as SessionInfo;
    } catch {
      return null;
    }
  }

  /** Save a session as a file of the domain config, keyed by server URL. */
  private async saveSession(session: SessionInfo): Promise<void> {
    await this.config.writeFile(CliWallet.sessionFileName(session.domain), JSON.stringify(session, null, 2));
  }

  /** One file per server, named by a digest of its URL: `session-<md5>.json`. */
  private static sessionFileName(serverUrl: string): string {
    return `session-${createHash('md5').update(serverUrl).digest('hex')}.json`;
  }

  /**
   * Create bot authentication header for a specific request.
   *
   * The signature covers the request: method, URI, audience host and a digest
   * of the body, plus a timestamp and a single-use nonce. A header minted for
   * one call cannot be replayed against a different endpoint, a different host,
   * or the same endpoint with a different body.
   *
   * The signed bytes are built by `client/bot-auth-message.mjs`, which is also
   * what the server verifier uses. Never inline the message here.
   *
   * Format: Authorization: Bot <base64-json>
   *
   * @param req.method  HTTP method
   * @param req.uri     path + query exactly as it will be sent
   * @param req.url     alternative to uri: a full URL, from which the uri and
   *                    audience host are derived
   * @param req.aud     audience host; defaults to the host in `req.url`
   * @param req.body    request body as sent — string, Buffer or undefined
   */
  async createBotAuthHeader(req: BotAuthRequest = {}): Promise<string> {
    const { botAuthorization } = await loadClientModule('bot-auth-message.mjs');
    return botAuthorization({
      sign: (m: string) => this.sign(m),
      address: this.address,
      method: req.method || 'POST',
      url: req.url, uri: req.uri, aud: req.aud,
      body: req.body === undefined || req.body === null ? undefined : req.body,
    });
  }

  /**
   * Export wallet data (for migration or backup)
   */
  toJSON() {
    return {
      domain: this.domainName,
      address: this.wallet.address,
      publicKey: this.wallet.publicKey,
      provider: this.domainConfig.provider
    };
  }
}