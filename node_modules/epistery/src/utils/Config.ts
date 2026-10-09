import fs from 'fs';
import fsp from 'fs/promises';
import { join } from 'path';
import ini from 'ini';
import { ethers } from 'ethers';
import {
  SECRET_DIR_MODE,
  SECRET_FILE_MODE,
  holdsSecrets,
  secureDir,
  secureFile,
  secureToSync,
  warnIfTooOpen,
} from './Permissions';
import { loadClientModule } from './clientModule';

/**
 * Epistery Config — async path-based configuration store.
 *
 * Filesystem-like config management, now async so the same interface can be
 * served by a remote authority:
 * - setPath('/') → ~/.epistery/config.ini
 * - setPath('/domain') → ~/.epistery/domain/config.ini
 * - setPath('/.ssl/domain') → ~/.epistery/.ssl/domain/config.ini
 *
 * `Config` is a thin facade that picks a backend at construction:
 *   - if the local bootstrap ~/.epistery/config.ini has [authority] url=…,
 *     or EPISTERY_CONFIG_URL is set → RemoteConfig (talks to epistery-authority)
 *   - otherwise → LocalConfig (the filesystem store; unchanged semantics)
 *
 * Every IO method is async because a remote/HSM custodian cannot answer
 * synchronously. `data` holds the snapshot from the last awaited load()/setPath().
 *
 * Usage:
 *   const config = new Config('epistery');
 *   await config.setPath('/wiki.rootz.global');   // loads
 *   config.data.verified = true;
 *   await config.save();
 */
export interface ConfigStore {
  data: any;
  getPath(): string;
  setPath(path: string): Promise<void>;
  load(): Promise<void>;
  read(path: string): Promise<any>;
  save(): Promise<void>;
  readFile(filename: string): Promise<Buffer>;
  writeFile(filename: string, data: string | Buffer): Promise<void>;
  exists(): Promise<boolean>;
  listPaths(): Promise<string[]>;
}

/** Normalize a path: leading slash, no trailing slash, lowercase. */
function normalizePath(path: string): string {
  path = path.trim();
  if (!path.startsWith('/')) path = '/' + path;
  if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
  return path.toLowerCase();
}

/**
 * LocalConfig — the filesystem backend under ~/.epistery. This is the original
 * Config behavior, with all IO made async. It is also what the epistery-authority
 * server mounts as its own storage backend (one implementation, not two).
 *
 * The tree holds wallet mnemonics and private keys in cleartext, so every
 * directory it creates is 0700 and every file it writes is 0600 — and a file
 * that already exists too open is tightened on write (see utils/Permissions).
 * `epistery permissions [--fix]` audits/repairs what is already on disk.
 */
export class LocalConfig implements ConfigStore {
  public readonly rootName: string;
  public readonly homeDir: string;
  public readonly configDir: string;

  private currentPath: string = '/';
  private currentDir: string;
  private currentFile: string;

  public data: any = {};

  constructor(rootName: string = 'epistery') {
    this.rootName = rootName;
    this.homeDir = (process.platform === 'win32' ? process.env.USERPROFILE : process.env.HOME) || '';
    this.configDir = join(this.homeDir, '.' + this.rootName);

    this.currentDir = this.configDir;
    this.currentFile = join(this.configDir, 'config.ini');

    // Bootstrap is synchronous: seed the root config so the very first run has
    // somewhere to read the authority URL from. Only this seed stays sync; all
    // subsequent IO is async.
    if (!fs.existsSync(this.currentFile)) {
      this.initializeSync();
    }
  }

  private initializeSync(): void {
    if (!fs.existsSync(this.currentDir)) {
      fs.mkdirSync(this.currentDir, { recursive: true, mode: SECRET_DIR_MODE });
    }
    // mkdir's mode is masked by umask, and an existing dir keeps its own mode,
    // so chmod is what actually guarantees 0700 here.
    secureToSync(this.currentDir, SECRET_DIR_MODE);

    const defaultContent = this.currentPath === '/' ? defaultIni : '';
    fs.writeFileSync(this.currentFile, defaultContent, { mode: SECRET_FILE_MODE });
    secureToSync(this.currentFile, SECRET_FILE_MODE);
    this.data = ini.decode(defaultContent);
  }

  public getPath(): string {
    return this.currentPath;
  }

  public async setPath(path: string): Promise<void> {
    path = normalizePath(path);
    this.currentPath = path;

    if (path === '/') {
      this.currentDir = this.configDir;
      this.currentFile = join(this.configDir, 'config.ini');
    } else {
      this.currentDir = join(this.configDir, path.slice(1));
      this.currentFile = join(this.currentDir, 'config.ini');
    }

    await this.load();
  }

  public async load(): Promise<void> {
    this.data = await LocalConfig.readIni(this.currentFile);
  }

  public async read(path: string): Promise<any> {
    path = normalizePath(path);
    const configFile = path === '/'
      ? join(this.configDir, 'config.ini')
      : join(this.configDir, path.slice(1), 'config.ini');
    return LocalConfig.readIni(configFile);
  }

  /**
   * A config that is ABSENT is empty ({}); a config that cannot be READ throws.
   * The two used to collapse into {} — and the next step after "no wallet in
   * this config" mints one and saves it, so one failed read at boot could
   * replace a domain's wallet (PredictableFailure: read-failed is not absent).
   */
  private static async readIni(file: string): Promise<any> {
    let text: string;
    try {
      text = await fsp.readFile(file, 'utf8');
    } catch (e: any) {
      if (e?.code === 'ENOENT') return {};
      throw new Error(`config read failed: ${file}: ${e?.message || e}`);
    }
    const data = ini.decode(text);
    if (holdsSecrets(data)) warnIfTooOpen(file);
    return data;
  }

  public async save(): Promise<void> {
    await fsp.mkdir(this.currentDir, { recursive: true, mode: SECRET_DIR_MODE });
    await fsp.writeFile(this.currentFile, ini.stringify(this.data), { mode: SECRET_FILE_MODE });
    // Repair the mode of a directory/file that predates this rule (or that a
    // permissive umask widened at create time).
    await secureDir(this.currentDir);
    await secureFile(this.currentFile);
  }

  public async readFile(filename: string): Promise<Buffer> {
    return fsp.readFile(join(this.currentDir, filename));
  }

  public async writeFile(filename: string, data: string | Buffer): Promise<void> {
    await fsp.mkdir(this.currentDir, { recursive: true, mode: SECRET_DIR_MODE });
    const target = join(this.currentDir, filename);
    // TLS keys under .ssl/ live here too — same owner-only rule.
    await fsp.writeFile(target, data, { mode: SECRET_FILE_MODE });
    await secureDir(this.currentDir);
    await secureFile(target);
  }

  public async exists(): Promise<boolean> {
    try {
      await fsp.access(this.currentFile);
      return true;
    } catch {
      return false;
    }
  }

  public async listPaths(): Promise<string[]> {
    try {
      const entries = await fsp.readdir(this.currentDir, { withFileTypes: true });
      return entries.filter(e => e.isDirectory()).map(e => e.name);
    } catch {
      return [];
    }
  }
}

/**
 * RemoteConfig — HTTP client to an epistery-authority server. Implements the
 * same ConfigStore interface; the authority mounts a LocalConfig behind it.
 *
 * Auth is the rivet key-exchange: the machine signs a challenge with its
 * device key, and the authority issues a bearer token (see epistery-authority
 * lib/auth.mjs). In Phase 1 config data (including the wallet mnemonic) is
 * still served; Phase 2 splits public from secret and adds /sign/*.
 */
export class RemoteConfig implements ConfigStore {
  public data: any = {};
  private currentPath: string = '/';
  private token: string | null = null;

  // Optional per-role subtree on the authority. When set (e.g. '/relay'), every
  // path the client uses is remapped under it: the client's '/' → authority
  // '/relay', '/relay.epistery.com' → '/relay/relay.epistery.com'. This lets a
  // role (and a pool of its instances) share one config + cert subtree without
  // colliding with other roles on the authority's root. Empty = no remap.
  private readonly basePath: string;

  constructor(
    private readonly baseUrl: string,
    private readonly machineAddress: string,
    private readonly signChallenge: (message: string) => Promise<string>,
    basePath: string = '',
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.basePath = (!basePath || basePath === '/') ? '' : normalizePath(basePath);
  }

  public getPath(): string {
    return this.currentPath;     // the client's logical path (unprefixed)
  }

  /** Map a client path into the authority's namespace under basePath. */
  private prefixed(path: string): string {
    const p = normalizePath(path);
    if (!this.basePath) return p;
    return p === '/' ? this.basePath : this.basePath + p;
  }

  private async authenticate(): Promise<void> {
    const fetch = (globalThis as any).fetch;
    const cRes = await fetch(`${this.baseUrl}/auth/challenge`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ machineAddress: this.machineAddress }),
    });
    if (!cRes.ok) throw new Error(`authority challenge failed: ${cRes.status}`);
    const { challenge } = await cRes.json();

    const { keyExchangeMessage } = await loadClientModule('key-exchange-message.mjs');
    const message = keyExchangeMessage({ address: this.machineAddress, challenge });
    const signature = await this.signChallenge(message);

    const vRes = await fetch(`${this.baseUrl}/auth/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ machineAddress: this.machineAddress, message, signature }),
    });
    if (!vRes.ok) throw new Error(`authority verify failed: ${vRes.status}`);
    this.token = (await vRes.json()).token;
  }

  private async authedFetch(pathAndQuery: string, init: any = {}): Promise<any> {
    const fetch = (globalThis as any).fetch;
    if (!this.token) await this.authenticate();
    const withAuth = () => ({ ...init, headers: { ...(init.headers || {}), authorization: `Bearer ${this.token}` } });
    let res = await fetch(this.baseUrl + pathAndQuery, withAuth());
    if (res.status === 401) {
      this.token = null;            // expired — re-auth once
      await this.authenticate();
      res = await fetch(this.baseUrl + pathAndQuery, withAuth());
    }
    return res;
  }

  public async setPath(path: string): Promise<void> {
    this.currentPath = normalizePath(path);
    await this.load();
  }

  public async load(): Promise<void> {
    this.data = await this.read(this.currentPath);
  }

  public async read(path: string): Promise<any> {
    const p = this.prefixed(path);
    const res = await this.authedFetch(`/config${p === '/' ? '/' : p}`);
    // Absent on the authority is empty; anything else that is not a success is a
    // failed read and throws — never an empty config that the caller then fills.
    if (res.status === 404) return {};
    if (!res.ok) throw new Error(`authority read failed: ${res.status} for ${p}`);
    return (await res.json()).data || {};
  }

  public async save(): Promise<void> {
    const p = this.prefixed(this.currentPath);
    const res = await this.authedFetch(`/config${p === '/' ? '/' : p}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ data: this.data }),
    });
    if (!res.ok) throw new Error(`authority save failed: ${res.status}`);
  }

  private filePrefix(): string {
    const p = this.prefixed(this.currentPath);
    return p === '/' ? '' : p;
  }

  public async readFile(filename: string): Promise<Buffer> {
    const res = await this.authedFetch(`/file${this.filePrefix()}/${filename}`);
    if (!res.ok) throw new Error(`authority file read failed: ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }

  public async writeFile(filename: string, data: string | Buffer): Promise<void> {
    const res = await this.authedFetch(`/file${this.filePrefix()}/${filename}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
      body: data,
    });
    if (!res.ok) throw new Error(`authority file write failed: ${res.status}`);
  }

  public async exists(): Promise<boolean> {
    const data = await this.read(this.currentPath);
    return !!data && Object.keys(data).length > 0;
  }

  public async listPaths(): Promise<string[]> {
    const p = this.prefixed(this.currentPath);
    const res = await this.authedFetch(`/paths${p === '/' ? '/' : p}`);
    if (!res.ok) return [];
    return (await res.json()).paths || [];
  }
}

/**
 * Config — the public facade. `new Config()` selects the backend synchronously
 * (reading only the local bootstrap), then delegates every async operation.
 * Existing call sites change only by adding `await`.
 */
export class Config implements ConfigStore {
  private readonly backend: ConfigStore;
  private readonly local: LocalConfig;

  constructor(rootName: string = 'epistery') {
    this.local = new LocalConfig(rootName);
    const authorityUrl = Config.resolveAuthorityUrl(rootName);
    if (authorityUrl) {
      const { machineAddress, sign } = Config.machineSigner(rootName);
      // Per-role subtree: this host's '/' maps under it on the authority, so a
      // pool of like role instances shares one config + cert subtree.
      const root = process.env.EPISTERY_CONFIG_ROOT
        || Config.readBootstrap(rootName)?.authority?.root || '';
      this.backend = new RemoteConfig(authorityUrl, machineAddress, sign, root);
    } else {
      this.backend = this.local;
    }
  }

  /** Read the local bootstrap config.ini synchronously (authority selection only). */
  private static readBootstrap(rootName: string): any {
    const homeDir = (process.platform === 'win32' ? process.env.USERPROFILE : process.env.HOME) || '';
    const file = join(homeDir, '.' + rootName, 'config.ini');
    try {
      return ini.decode(fs.readFileSync(file, 'utf8'));
    } catch {
      return {};
    }
  }

  private static resolveAuthorityUrl(rootName: string): string | null {
    if (process.env.EPISTERY_CONFIG_URL) return process.env.EPISTERY_CONFIG_URL;
    const boot = Config.readBootstrap(rootName);
    return boot?.authority?.url || null;
  }

  /**
   * Build the machine signer used to authenticate to the authority. The machine
   * rivet key lives in the local bootstrap [authority] section (Phase 1). A
   * future TPM-backed key replaces this without changing the call site.
   */
  private static machineSigner(rootName: string): { machineAddress: string; sign: (m: string) => Promise<string> } {
    const boot = Config.readBootstrap(rootName);
    const a = boot?.authority || {};
    let wallet: ethers.Wallet;
    if (a.machineMnemonic) {
      wallet = ethers.Wallet.fromMnemonic(a.machineMnemonic);
    } else if (a.machineKey) {
      wallet = new ethers.Wallet(a.machineKey);
    } else {
      throw new Error(
        'Config: [authority] url is set but no machine credential ([authority] machineMnemonic or machineKey) is configured to authenticate to it.',
      );
    }
    return { machineAddress: wallet.address, sign: (m: string) => wallet.signMessage(m) };
  }

  // Local-machine facts (always the bootstrap LocalConfig, even in remote mode):
  // these are filesystem paths some callers need (e.g. CliWallet session dir).
  public get rootName(): string { return this.local.rootName; }
  public get homeDir(): string { return this.local.homeDir; }
  public get configDir(): string { return this.local.configDir; }

  public get data(): any { return this.backend.data; }
  public set data(v: any) { this.backend.data = v; }

  public getPath(): string { return this.backend.getPath(); }
  public setPath(path: string): Promise<void> { return this.backend.setPath(path); }
  public load(): Promise<void> { return this.backend.load(); }
  public read(path: string): Promise<any> { return this.backend.read(path); }
  public save(): Promise<void> { return this.backend.save(); }
  public readFile(filename: string): Promise<Buffer> { return this.backend.readFile(filename); }
  public writeFile(filename: string, data: string | Buffer): Promise<void> { return this.backend.writeFile(filename, data); }
  public exists(): Promise<boolean> { return this.backend.exists(); }
  public listPaths(): Promise<string[]> { return this.backend.listPaths(); }
}

const defaultIni =
`[profile]
name=
email=

[ipfs]
url=https://rootz.digital/api/v0

; Chain used for wallets created by \`epistery initialize\` when it isn't given
; one. Change it with \`epistery set-default-chain <chainId|name>\`; list the
; supported chains with \`epistery chains\`.
[default]
defaultChainId=137

[default.provider]
chainId=137
name=Polygon Mainnet
rpc=https://polygon-bor-rpc.publicnode.com
nativeCurrencyName=POL
nativeCurrencySymbol=POL
nativeCurrencyDecimals=18

; Additional supported chains (see \`epistery chains\` for the live list):
; Ethereum Mainnet (ETH):
;   chainId=1
;   name=Ethereum Mainnet
;   rpc=https://ethereum-rpc.publicnode.com
;   nativeCurrencyName=Ether
;   nativeCurrencySymbol=ETH
;   nativeCurrencyDecimals=18
;
; Japan Open Chain (JOC):
;   chainId=81
;   name=Japan Open Chain
;   rpc=https://rpc-2.japanopenchain.org:8545
;   nativeCurrencyName=Japan Open Chain Token
;   nativeCurrencySymbol=JOC
;   nativeCurrencyDecimals=18
;
; Per-chain fee policy (optional). Bump these only after a market move
; legitimately pushes the network past the cap; the default is meant to
; be a circuit-breaker, not a normal operating point.
;   [default.rpc.137.policy]
;   maxFeePerGasGwei=1000          ; refuse to send if Polygon wants more
;   minPriorityFeeGwei=25         ; Polygon RPC floor (don't lower)
;   [default.rpc.81.policy]
;   maxGasPriceGwei=1000           ; legacy-chain analogue (JOC)

; Shared Configuration Authority (optional). When set, Config reads/writes
; through the epistery-authority server instead of the local filesystem, so
; this host becomes a stateless pool member. EPISTERY_CONFIG_URL overrides url.
;   [authority]
;   url=https://epistery-authority-1.internal:4500
;   machineMnemonic=...            ; this machine's rivet (or machineKey=0x…)
;   root=/relay                    ; optional: this role's subtree on the authority
;                                  ; (a pool of like instances shares it). EPISTERY_CONFIG_ROOT overrides.
`;
