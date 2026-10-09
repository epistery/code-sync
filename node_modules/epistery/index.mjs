import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Epistery } from "./dist/epistery.js";
import { Utils } from "./dist/utils/Utils.js";
import { Config } from "./dist/utils/Config.js";
import { CliWallet } from "./dist/utils/CliWallet.js";
import { chainFor, registerChain, configuredChains, attestationConfig, defaultChainId, defaultChain, findChain, setDefaultChain, providerConfigFor, rootProvider, serverRpcOf, publicRpcOf, Chain } from "./dist/chains/index.js";
import * as sessionJar from "./session-jar.mjs";
// Permission floor for ~/.epistery (wallet keys are cleartext there): hosts can
// audit/repair the tree at startup the same way `epistery permissions` does.
import { auditTree, secureTree, formatMode } from "./dist/utils/Permissions.js";
import createRoutes from "./routes/index.mjs";
// The canonical storage-write message builder (shared by every signer and the
// relay verifier). Lives in client/ as pure ESM so browsers can import the same
// file; re-exported below for the ergonomic `import { storageWriteMessage } from
// 'epistery'`. Server consumers may also import it directly from
// 'epistery/client/storage-message.mjs' to avoid loading the full entry.
import { storageWriteMessage } from "./client/storage-message.mjs";
// The canonical Boost statement — the signed claim that releases gas money from
// an identity's treasury to one of its own devices. Same reason as the two
// modules above: the bytes are defined once and imported, never re-inlined,
// because BoostVerifier.sol recomputes them on chain and a drift breaks every
// Boost ever issued. See contracts/BoostVerifier.sol.
import { BOOST_TYPE_STRING, boostTypehash, boostDigest, issueBoost } from "./client/boost-message.mjs";
// The canonical origin certificate — the domain's countersignature on a device
// key, {rivet, domain, ts} signed by the domain's own wallet at key exchange.
// Same reason again: a rivet key is origin-scoped, but a domain NAME asserted by
// page JS is a commitment rather than proof, and every verifier of that proof has
// to rebuild the identical bytes. See client/origin-certificate.mjs.
import {
  ORIGIN_CERT_TAG,
  ORIGIN_CERT_VERSION,
  ORIGIN_CERT_MAX_AGE_MS,
  originCertificateMessage,
  issueOriginCertificate,
  verifyOriginCertificate,
} from "./client/origin-certificate.mjs";
// The canonical `Bot` auth message — the same module the CLI signs with. Same
// reason as storage-message.mjs: one definition, imported by both sides, never
// re-inlined. See client/bot-auth-message.mjs for the wire shape.
import {
  audienceFor,
  parseBotEnvelope,
  messageForEnvelope,
  EMPTY_BODY_SHA256,
} from "./client/bot-auth-message.mjs";
import { createHash } from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// How far a bot envelope's `ts` may sit from our clock, and how long a nonce is
// remembered. Bot auth is a live-request credential, not an archival record —
// the window is deliberately short. (Archival signing has different needs and
// belongs in the signed-result envelope, not here.)
const BOT_AUTH_MAX_AGE_MS = 120_000;
const BOT_AUTH_MAX_SKEW_MS = 30_000;

/**
 * Replay store. A nonce is single-use inside its validity window; past the
 * window the envelope fails on freshness anyway, so entries are dropped.
 *
 * The store is one method:
 *
 *   claim(nonce, expiresAtMs) -> boolean | Promise<boolean>
 *     true  — the nonce was NOT seen before and is now reserved until expiry
 *     false — already reserved: a replay
 *
 * `claim` MUST be atomic — check-and-reserve in one indivisible step. That is
 * what lets it be the single replay gate, with no check-then-set gap for two
 * concurrent replays to slip through.
 *
 * The default below is in-process, and single-use only WITHIN one process. A
 * multi-instance deployment (e.g. the relay behind a load balancer) MUST inject
 * a shared store via setBotNonceStore — otherwise a header replayed against a
 * different instance is not caught. createMongoNonceStore is a ready shared
 * implementation.
 */
function createInProcessNonceStore() {
  const seen = new Map(); // nonce -> expiresAtMs
  return {
    // Synchronous: the whole check-and-reserve runs in one tick with nothing
    // interleaved — atomic by construction on a single event loop.
    claim(nonce, expiresAtMs) {
      const now = Date.now();
      const exp = seen.get(nonce);
      if (exp !== undefined && exp > now) return false; // still valid -> replay
      seen.set(nonce, expiresAtMs);
      if (seen.size > 10000) {
        for (const [k, v] of seen) if (v <= now) seen.delete(k);
      }
      return true;
    },
  };
}

let _botNonceStore = createInProcessNonceStore();

/**
 * Replace the bot-auth replay store. Call once at startup, before serving.
 * The store must implement `claim(nonce, expiresAtMs)` atomically (see above).
 * A multi-instance host MUST call this with a shared store.
 */
export function setBotNonceStore(store) {
  if (!store || typeof store.claim !== "function") {
    throw new Error(
      "setBotNonceStore: store must implement claim(nonce, expiresAtMs)",
    );
  }
  _botNonceStore = store;
}

/** A fresh in-process store (the default). Exported so a host or test can reset. */
export { createInProcessNonceStore };

/**
 * A shared, cross-instance nonce store backed by a MongoDB collection. The
 * document `_id` IS the nonce, so a duplicate insert is rejected atomically by
 * the server (E11000) — that IS the replay check, and it holds across every
 * instance writing the same collection. A TTL index on `expireAt` lets Mongo
 * purge spent nonces on its own.
 *
 * No `mongodb` dependency here: the collection is duck-typed (insertOne +
 * createIndex), so the host passes in whatever driver handle it already has:
 *
 *   import { setBotNonceStore, createMongoNonceStore } from 'epistery';
 *   setBotNonceStore(createMongoNonceStore(db.collection('bot_nonces')));
 *
 * Fail-closed: if the store throws (Mongo unreachable), verifyBotAuth catches
 * it and rejects the request rather than admit an unverifiable nonce.
 */
export function createMongoNonceStore(collection, { ensureIndex = true } = {}) {
  let indexed = ensureIndex ? null : Promise.resolve();
  function ensure() {
    if (!indexed) {
      indexed = Promise.resolve(
        collection.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 }),
      ).catch(() => {}); // a missing TTL index only delays purge, never correctness
    }
    return indexed;
  }
  return {
    async claim(nonce, expiresAtMs) {
      await ensure();
      try {
        await collection.insertOne({ _id: nonce, expireAt: new Date(expiresAtMs) });
        return true; // first writer wins
      } catch (e) {
        if (e && (e.code === 11000 || e.code === 11001)) return false; // duplicate -> replay
        throw e; // real failure -> caller fails closed
      }
    },
  };
}

/**
 * Body parsers consume the request stream, so the exact bytes a signature
 * commits to (bot auth, storage writes) are gone by the time the auth
 * middleware runs. That raw body is epistery's OWN input, so epistery captures
 * it itself — see attach()/_installBotBodyCapture, which parses+captures the
 * body ONLY for requests carrying an `Authorization: Bot` header (non-bot
 * traffic is never touched). A host that mounts epistery does NOT have to
 * remember any express.json({ verify: captureRawBody }) incantation; if it
 * forgot, a bodied bot request would silently fail, and that obscure
 * requirement is exactly the foot-gun this ownership removes.
 *
 * This function stays exported for the one legitimate external case: a server
 * that verifies epistery-signed data WITHOUT installing epistery (e.g. a relay
 * doing its own storage-message check). There, and only there, the operator
 * wires the hook into their own parser by hand.
 */
export function captureRawBody(req, _res, buf) {
  if (buf && buf.length) req.rawBody = Buffer.from(buf);
}

/** Raw bytes for hashing, or null when the body was consumed unrecoverably. */
function _botRawBody(req) {
  if (req.rawBody !== undefined && req.rawBody !== null) {
    return Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.from(String(req.rawBody), "utf8");
  }
  const b = req.body;
  if (b === undefined || b === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(b)) return b;
  if (typeof b === "string") return Buffer.from(b, "utf8");
  // An object here means a parser ran without captureRawBody. Re-serialising it
  // would not reproduce the signed bytes (key order, whitespace, unicode escapes),
  // so we refuse rather than guess.
  if (typeof b === "object" && Object.keys(b).length === 0) return Buffer.alloc(0);
  return null;
}

/**
 * Verify an `Authorization: Bot` header against the request it claims to
 * authorise. The single implementation — both resolveClient() and the attach()
 * middleware call this, so there is exactly one place identity is decided.
 *
 * Exported so non-express hosts (WebSocket upgrades, other frameworks) verify
 * with the same code path rather than re-deriving it — the README's rule that
 * no consumer may duplicate identity resolution applies to us first.
 *
 * `req` needs only: headers.authorization, method, originalUrl|url, hostname or
 * headers.host, and rawBody|body.
 *
 * Returns the episteryClient shape, or null. Never throws.
 *
 * Today the bot wire proves a signer only; contractAddress stays null. A future
 * bot path that wants to claim a contract signs the claim and the server
 * verifies isAuthorized — same shape as cookie sessions.
 */
export async function verifyBotAuth(req, nowMs) {
  const header = req?.headers?.authorization;
  if (!header || !header.startsWith("Bot ")) return null;
  const now = nowMs ?? Date.now();
  try {
    const decoded = Buffer.from(header.substring(4), "base64").toString("utf8");
    const parsed = JSON.parse(decoded);
    // Two wires share the scheme name: the relay's storage-write credential is
    // also `Bot <base64 JSON>`, with a signed `message` and no version. That is
    // not ours to judge (the relay verifies it); it is simply not a bot-auth
    // envelope, and says nothing about who the caller is here.
    if (parsed && typeof parsed === "object" && parsed.v === undefined && typeof parsed.message === "string") return null;
    const env = parseBotEnvelope(parsed);
    if (!env) {
      console.warn("[epistery] Bot auth rejected: malformed or unsupported envelope version");
      return null;
    }

    // Freshness before anything expensive.
    const age = now - env.ts;
    if (age > BOT_AUTH_MAX_AGE_MS || age < -BOT_AUTH_MAX_SKEW_MS) {
      console.warn("[epistery] Bot auth rejected: stale or future-dated envelope");
      return null;
    }

    // Audience: a signature minted for another host does not verify here.
    const host = req.hostname || req.headers?.host?.split(":")[0] || "";
    if (env.aud !== audienceFor(host)) {
      console.warn(`[epistery] Bot auth rejected: audience ${env.aud} != ${audienceFor(host)}`);
      return null;
    }

    // Method and URI: a signature for one call does not authorise another.
    const method = (req.method || "").toUpperCase();
    const uri = req.originalUrl || req.url || "";
    if (env.method !== method || env.uri !== uri) {
      console.warn("[epistery] Bot auth rejected: method/uri mismatch");
      return null;
    }

    // Body commitment.
    const raw = _botRawBody(req);
    if (raw === null) {
      console.warn(
        "[epistery] Bot auth rejected: request body was parsed without captureRawBody, so the signed bytes cannot be reproduced. Mount express.json({ verify: captureRawBody }).",
      );
      return null;
    }
    const bodyHash = raw.length === 0
      ? EMPTY_BODY_SHA256
      : createHash("sha256").update(raw).digest("hex");
    if (bodyHash !== env.bodyHash) {
      console.warn("[epistery] Bot auth rejected: body digest mismatch");
      return null;
    }

    const { ethers } = await import("ethers");
    const recovered = ethers.utils.verifyMessage(messageForEnvelope(env), env.signature);
    if (recovered.toLowerCase() !== env.address.toLowerCase()) {
      console.warn("[epistery] Bot auth rejected: signature does not recover the claimed address");
      return null;
    }

    // Replay is the LAST gate, one atomic step: claim the nonce or reject. After
    // signature verification, so only an authentic request can consume a nonce
    // (an unauthenticated flood can't burn the store), and there is no
    // check-then-set window. With a shared store (setBotNonceStore) this holds
    // across every instance; with the in-process default, within one process.
    const nonceOk = await _botNonceStore.claim(
      env.nonce,
      now + BOT_AUTH_MAX_AGE_MS + BOT_AUTH_MAX_SKEW_MS,
    );
    if (!nonceOk) {
      console.warn("[epistery] Bot auth rejected: nonce replay");
      return null;
    }

    return {
      signerAddress: env.address,
      contractAddress: null,
      identityAddress: env.address,
      authenticated: true,
      authType: "bot",
    };
  } catch (error) {
    console.warn("[epistery] Bot auth rejected:", error.message);
    return null;
  }
}

/**
 * Resolve the _epistery cookie session a request is entitled to — the ONE
 * implementation, shared by the attach() middleware and resolveClient(), so an
 * ordinary request and a WebSocket upgrade never disagree about who a tab is.
 *
 * The cookie is a jar of slots, one per tab (see session-jar.mjs). The request
 * says which slot it means: X-Epistery-Tab on fetch/XHR, ?_tab= on an upgrade,
 * nothing at all on a document navigation. Naming a slot the jar does not hold
 * yields null — never the default. A tab that cannot be recognised handshakes
 * again; it does not inherit the identity another tab proved.
 *
 * Returns the episteryClient shape, or null. Never throws.
 */
export function sessionFromJar(req) {
  const jar = sessionJar.decode(sessionJar.cookieFromRequest(req));
  const s = sessionJar.select(jar, sessionJar.tabFromRequest(req));
  if (!s?.signerAddress) return null;
  return {
    signerAddress: s.signerAddress,
    contractAddress: s.contractAddress || null,
    identityAddress: s.contractAddress || s.signerAddress,
    publicKey: s.publicKey,
    authenticated: !!s.authenticated,
    authType: "cookie",
  };
}

// Helper function to get or create domain configurations src/utils/Config.ts system
async function getDomainConfig(domain) {
  // InitServerWallet warms the per-domain wallet cache (and creates+persists a
  // wallet on first touch). Awaiting it here keeps the synchronous `get signer()`
  // getter able to read the cache via Utils.GetServerWalletFor.
  await Utils.InitServerWallet(domain);
  return await Utils.GetDomainInfo(domain);
}

// Where a host is discovered (RFC 8615), and the default mount of its routes.
export const WELL_KNOWN_PATH = "/.well-known/epistery";

class EpisteryAttach {
  constructor(options = {}) {
    this.options = options;
    this.domain = null;
    this.domainName = null;
    this.config = new Config();
  }

  static async connect(options) {
    const attach = new EpisteryAttach(options);
    await Epistery.initialize();
    return attach;
  }

  async setDomain(domain) {
    this.domainName = domain;
    this.domain = await getDomainConfig(domain);
  }

  /**
   * Get the server wallet as an ethers.js Signer for the current domain.
   * Used by OAuthServer, MCPServer, and agents that need signing capability.
   */
  get signer() {
    if (!this.domainName) return null;
    // Synchronous read of the cache warmed by setDomain()→getDomainConfig()→
    // InitServerWallet. Keeps `.signer` a sync getter despite the async config.
    return Utils.GetServerWalletFor(this.domainName) || null;
  }

  /**
   * Resolve a session from any HTTP-like request — works in the express
   * middleware path (where `req.cookies` is populated by cookie-parser) and
   * in raw contexts like a WebSocket upgrade (where only `req.headers.cookie`
   * is available). Mirrors the auth pathways the attach() middleware uses,
   * minus the name enrichment, which stays a middleware-only concern.
   *
   * Returns {signerAddress, identityAddress, contractAddress, publicKey,
   * authenticated, authType} or null. identityAddress is derived as
   * contractAddress || signerAddress and is always non-null when the rest is.
   */
  async resolveClient(req) {
    // 1. Bot auth (CLI / programmatic). One implementation, shared with the
    // attach() middleware — see verifyBotAuth above.
    const bot = await verifyBotAuth(req);
    if (bot) return bot;

    // 2. Session cookie (_epistery) — a jar of one proven session PER TAB, so
    // two tabs can be two different rivets. The request names its slot with
    // X-Epistery-Tab, or ?_tab= on a WebSocket upgrade, which carries no
    // headers; naming nothing means the default slot. See session-jar.mjs for
    // why a named-but-absent slot resolves to NO session rather than falling
    // back — it is the whole point.
    return sessionFromJar(req);
  }

  async attach(app, rootPath, options = {}) {
    this.rootPath = rootPath || WELL_KNOWN_PATH;
    app.locals.epistery = this;

    // Capture the raw bytes a bot signature commits to — but ONLY for requests
    // that actually present a Bot credential (the sole consumer of req.rawBody
    // in epistery is verifyBotAuth). Every other request is left completely
    // untouched: its body is not read here, so uploads, streams, proxies and
    // the host's own parser (and the host's own size limit) all behave exactly
    // as before. See _installBotBodyCapture.
    this._installBotBodyCapture(app, options.bodyLimit || "100mb");

    // The domain. A host is ONE identity: the domain it pinned with setDomain
    // is the domain of every request — the shared state (wallet, config,
    // certificate) is not switched per request, where two concurrent requests
    // for different names once left them out of step with each other. A host
    // that pinned no domain is misconfigured and says so; it does not take the
    // first Host header it sees as its identity. A multi-domain host serving
    // many identities from one process asks for the per-request switch
    // explicitly: attach(app, root, { domains: 'request' }).
    const perRequest = options.domains === "request";
    app.use(async (req, res, next) => {
      const ep = req.app.locals.epistery;
      if (perRequest) {
        // req.hostname respects Express trust-proxy and X-Forwarded-Host,
        // which is required for internal proxies (MCP loopback fetch).
        // Falls back to raw Host header for non-proxied requests.
        const hostname = req.hostname || req.headers.host?.split(":")[0] || "localhost";
        if (ep.domainName !== hostname) await ep.setDomain(hostname);
      } else if (!ep.domainName) {
        res.status(503).json({ error: "epistery: this host has pinned no domain — the server calls epistery.setDomain(<its hostname>) after attach(), or attaches with { domains: 'request' } to serve one identity per hostname" });
        return;
      }
      next();
    });

    // Authentication middleware — sets req.episteryClient to the three-fact
    // shape: { signerAddress, contractAddress, identityAddress, publicKey,
    // authenticated, authType }. signerAddress is the proven rivet,
    // contractAddress is a verified IdentityContract (or null), and
    // identityAddress is derived (contractAddress || signerAddress).
    // Downstream code authorizes against identityAddress.
    app.use(async (req, res, next) => {
      // 1. Bot authentication (CLI / programmatic). Signer-only today;
      // no contract claim path in the bot wire. Single implementation —
      // the same verifyBotAuth() resolveClient() uses.
      if (!req.episteryClient) {
        const bot = await verifyBotAuth(req);
        if (bot) req.episteryClient = bot;
      }

      // 2. Session cookie (_epistery). Set at /connect after signer proof and
      // (if a contract was claimed) on-chain isAuthorized verification. One
      // slot per tab — the same single resolver resolveClient() uses, so a
      // middleware request and a WebSocket upgrade can never disagree about
      // who a tab is.
      if (!req.episteryClient) {
        const session = sessionFromJar(req);
        if (session) req.episteryClient = session;
      }
      next();
    });

    // Mount routes - RFC 8615 compliant well-known URI
    app.use(this.rootPath, this.routes());

    // RFC 8615: the well-known location is where a stranger discovers this host
    // regardless of where the host chose to mount the routes. A host mounted at
    // its root (the console) still answers here, and the answer says the root,
    // so a client (the CLI's key exchange) asks for it rather than assuming it.
    if (this.rootPath !== WELL_KNOWN_PATH) {
      app.get([WELL_KNOWN_PATH, `${WELL_KNOWN_PATH}/`], (req, res) => res.json(this.buildStatus()));
    }
  }

  /**
   * Capture the raw request bytes bot-auth verification needs — and ONLY for
   * requests that carry an `Authorization: Bot` header. A bot request is one
   * epistery is going to read to authorise anyway, so parsing its body here is
   * not "eating" anything the app wanted to stream. Every non-bot request falls
   * straight through untouched: we never read its stream, so the host's own
   * parser, size limit, uploads, proxies and streaming routes are unaffected.
   *
   * Mechanism: a single guard middleware, moved ahead of the host's parsers
   * (just after Express's own query/init layers) so it precedes any parser the
   * host mounted, regardless of when attach() ran or which Express major the
   * host is on (v4 keeps app._router, v5 uses app.router — see _routerStack).
   * For a bot request it invokes json/urlencoded parsers (content-type gated,
   * a no-op on a non-matching type) carrying captureRawBody, and then marks the
   * request `_body` so a host parser mounted anyway no-ops (body-parser 1.x
   * skips once req._body is set) and a bot JSON body is parsed exactly once.
   * The mark is set only when a parser actually read the stream, so a bot body
   * this package left alone still reaches the host's own reader. Because only bot requests reach these
   * parsers, `limit` (default 100mb, generous on purpose) governs bot bodies
   * only — it never overrides the host's limit for ordinary traffic.
   *
   * Idempotent: guarded so repeated attach()/multi-domain setups install once.
   */
  _installBotBodyCapture(app, limit) {
    if (app.locals._episteryBotBodyCapture) return;
    app.locals._episteryBotBodyCapture = true;

    const jsonParser = express.json({ limit, verify: captureRawBody });
    const urlParser = express.urlencoded({ extended: true, limit, verify: captureRawBody });

    const guard = (req, res, next) => {
      const auth = req.headers?.authorization;
      // Not a bot request → do not touch the body at all.
      if (!auth || !auth.startsWith("Bot ")) return next();
      // Bot request → capture raw bytes via the matching parser (each self-skips
      // if the content-type does not match, leaving e.g. a multipart body alone).
      jsonParser(req, res, (err) => {
        if (err) return next(err);
        urlParser(req, res, (err2) => {
          if (err2) return next(err2);
          // Leave the marker body-parser 1.x uses to know a body is already
          // parsed. 2.x — which this package parses with — neither sets nor
          // reads it, so without this a 1.x host (Express 4: console, scan)
          // sees an unparsed request, re-reads a drained stream, and every
          // bodied bot request dies as "stream is not readable" from raw-body.
          //
          // ONLY when the stream was actually consumed. The parsers above
          // self-skip on a non-matching content-type, and a skipped parser
          // leaves the stream unread (readableEnded false). Setting the marker
          // then would make a host's own express.raw() skip too, and a bot
          // octet-stream body would never be read by anyone — the exact
          // behaviour #34 proved intact. `readableEnded` asks whether the body
          // was read rather than re-deriving which content-types matched.
          if (req.readableEnded) req._body = true;
          next();
        });
      });
    };

    app.use(guard);

    // Move the guard ahead of any body parser the host already mounted. If we
    // can't reach the router stack, leave the guard where it is — it is still
    // correct when attach() runs before the host's own parser.
    const stack = this._routerStack(app);
    if (!stack) {
      console.warn(
        "[epistery] could not reorder bot-body capture (unrecognised router). " +
          "If a host body parser runs before epistery.attach(), a bodied bot request may be refused.",
      );
      return;
    }

    // The guard is the layer app.use() just appended.
    const [layer] = stack.splice(stack.length - 1, 1);
    // Insert it after Express's own leading layers — `query`/`expressInit` on
    // Express 4, none on Express 5 — so it never runs before req/res are set up,
    // but still precedes the host's body parser.
    let at = 0;
    while (at < stack.length && (stack[at].name === "query" || stack[at].name === "expressInit")) at++;
    stack.splice(at, 0, layer);
  }

  /**
   * The active router's middleware stack, or null if it cannot be reached.
   * Express 4 keeps it on app._router and makes app.router a getter that THROWS
   * ("'app.router' is deprecated!"); Express 5 removed app._router and exposes
   * app.router. Resolve _router first so we never trip the v4 throw.
   */
  _routerStack(app) {
    let router = app._router;
    if (!router) {
      try {
        router = app.router;
      } catch {
        router = null;
      }
    }
    return router && Array.isArray(router.stack) ? router.stack : null;
  }

  /**
   * Build status JSON object
   * @returns {Object} Status object with server, client, and ipfs info
   */
  buildStatus() {
    // What this host says about itself: its wallet and the chain it is
    // configured on, as configured — null where nothing is configured, never a
    // default chain or endpoint standing in for one.
    const d = this.domain;
    const p = d?.provider || {};
    const nativeCurrency = p.nativeCurrencySymbol || p.nativeCurrency?.symbol
      ? {
        symbol: p.nativeCurrencySymbol || p.nativeCurrency?.symbol,
        name: p.nativeCurrencyName || p.nativeCurrency?.name || p.nativeCurrencySymbol || p.nativeCurrency?.symbol,
        decimals: Number(p.nativeCurrencyDecimals ?? p.nativeCurrency?.decimals) || 18,
      }
      : null;
    return {
      // Where this host mounted epistery: a client builds the handshake URL from
      // this, never from an assumed path.
      epistery: { rootPath: this.rootPath || WELL_KNOWN_PATH, connect: `${(this.rootPath || WELL_KNOWN_PATH).replace(/\/$/, "")}/connect` },
      server: {
        walletAddress: d?.wallet?.address || null,
        publicKey: d?.wallet?.publicKey || null,
        provider: p.name || null,
        chainId: p.chainId != null ? String(p.chainId) : null,
        rpc: p.publicRpc || p.rpc || null,
        nativeCurrency,
      },
      client: {},
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Creates and returns the router with all Epistery routes
   *
   * Route structure (all mounted under /.well-known/epistery/):
   *   /                     - Status (JSON/HTML)
   *   /status               - Status page (HTML)
   *   /lib/:module          - Client library files
   *   /artifacts/:file      - Contract artifacts
   *   /connect              - Key exchange (GET: the session's facts; POST: the handshake)
   *   /fido/blob            - PRF-wrapped rivet key blobs
   *
   * @returns {express.Router}
   */
  routes() {
    return createRoutes(this);
  }
}

export { EpisteryAttach as Epistery, Config, chainFor, registerChain, configuredChains, defaultChainId, Chain };
// The CLI (@epistery/cli) is a separate package; this is the surface it uses —
// the domain wallet as a member (CliWallet), chain selection, key-file modes.
export { CliWallet, defaultChain, findChain, setDefaultChain, providerConfigFor, rootProvider, serverRpcOf, publicRpcOf };
// How a caller reaches the chain for an attestation read (EpisteryChainReads): the
// owned endpoints from config, the reader over them, and the one classifier of a
// failed read versus the chain's answer.
export { attestationConfig };
export { chainReader, isChainReadFailure, ROLE, ROLE_NAME, roleName } from './client/chain-read.mjs';
export { auditTree, secureTree, formatMode };
export { storageWriteMessage };
// The rest of the storage-write wire and the key-exchange message — one home each
// (EpisteryRefactor3Q26Review C2, C7): the credential envelope encode/parse, the
// message parser, the body hash, the address shape.
export {
  STORAGE_WRITE_TAG, parseStorageWriteMessage, encodeStorageCredential, decodeStorageCredential,
  storageAuthorization, signStorageWrite, sha256hex, ADDRESS_RE, isAddress, base64urlEncode, base64urlDecode,
} from './client/storage-message.mjs';
export { keyExchangeMessage } from './client/key-exchange-message.mjs';
// The one peer-encryption and content construction (wraps and sealed records).
export {
  randomKey, ecdhShared, aesKeyFromShared, sealWithKey, openWithKey, sealWithShared, openWithShared,
  wrapKey, unwrapKey, encryptBytes, decryptBytes, encryptText, decryptText,
} from './client/peer-cipher.mjs';
// The bot-auth header, built for any signer.
export { botAuthorization, botAuthMessage, audienceFor, parseBotEnvelope, EMPTY_BODY_SHA256 } from './client/bot-auth-message.mjs';
export { BOOST_TYPE_STRING, boostTypehash, boostDigest, issueBoost };
export {
  ORIGIN_CERT_TAG,
  ORIGIN_CERT_VERSION,
  ORIGIN_CERT_MAX_AGE_MS,
  originCertificateMessage,
  issueOriginCertificate,
  verifyOriginCertificate,
};
