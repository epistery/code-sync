import express from "express";
import { createRequire } from "module";
import { Epistery } from "../dist/epistery.js";
import * as jar from "../session-jar.mjs";
import { issueOriginCertificate } from "../client/origin-certificate.mjs";
import { chainReader, isChainReadFailure } from "../client/chain-read.mjs";
import { attestationConfig } from "../dist/chains/index.js";

const require = createRequire(import.meta.url);
const ethers = require("ethers");

// A contract claim is verified on chain through core's own attestation reader —
// the owned nodes from config, k-of-n at the domain's quorum — never a raw
// provider or an environment variable. One reader per chain, built on first use.
const _readers = new Map();
async function readerFor(chainId) {
  if (!chainId) throw Object.assign(new Error("no chain configured for this domain"), { code: "CHAIN_UNREACHABLE" });
  const k = String(chainId);
  if (!_readers.has(k)) {
    const { rpcs, quorum } = await attestationConfig(chainId);
    if (!rpcs?.length) throw Object.assign(new Error(`no attestation endpoints configured for chain ${chainId} ([chains.<name>] attest[])`), { code: "CHAIN_UNREACHABLE" });
    _readers.set(k, chainReader({ rpcs, quorum, chainId, ethers }));
  }
  return _readers.get(k);
}

/**
 * Connect routes - key exchange and wallet creation
 * @param {Object} epistery - The EpisteryAttach instance
 * @returns {express.Router}
 */
export default function connectRoutes(epistery) {
  const router = express.Router();

  // Session check — surface the three facts the middleware exposes, no more.
  // Witness compares its current identityAddress against this; matching means
  // the cookie already names us, so no re-handshake needed. The middleware
  // resolved this against the CALLING TAB's slot, so a tab being a different
  // rivet sees {} here and goes on to handshake for itself.
  router.get("/connect", (req, res) => {
    const c = req.episteryClient;
    if (!c) return res.json({});
    res.json({
      signerAddress: c.signerAddress,
      identityAddress: c.identityAddress,
      contractAddress: c.contractAddress,
      ...(c.name ? { name: c.name } : {}),
    });
  });

  // Key exchange endpoint - handles POST requests for key exchange
  router.post("/connect", async (req, res) => {
    try {
      const data = req.body || {};

      // The domain's connected signer — the one wallet this host speaks as.
      const signer = epistery.signer;
      if (!signer) {
        return res.status(500).json({ error: "Server wallet not found" });
      }

      // Handle key exchange request
      const keyExchangeResponse = await Epistery.handleKeyExchange(data, signer);

      if (!keyExchangeResponse) {
        return res.status(401).json({
          error: "Key exchange failed - invalid client credentials",
        });
      }

      // Contract claim — when present, ALWAYS verified on-chain. No "is
      // contract == signer? then skip" shortcut: the wire never overloads
      // a single field, so the verifier never has to guess what the client
      // meant. The chain is truth; we ask it directly.
      //
      // The IdentityContract is read on the host's chain (the domain's
      // configured chain), through the attestation reader; `isRivet` is the
      // one vouching hop — a rivet of the contract, or of an identity the
      // contract admits as a signer.
      let verifiedContractAddress = null;
      if (data.contractAddress) {
        try {
          const reader = await readerFor(epistery.domain?.provider?.chainId);
          const isAuth = await reader.isRivet(data.contractAddress, data.signerAddress, { fresh: true });
          if (!isAuth) {
            return res.status(401).json({
              error:
                "Identity contract does not authorize this signer (isAuthorized returned false)",
            });
          }
          verifiedContractAddress = data.contractAddress;
        } catch (e) {
          // A CHAIN-READ FAILURE is NOT an authorization decision — we simply
          // could not ask the chain. Returning 401 here told clients "you are
          // not authorized" and, downstream, made the console offer to ERASE the
          // device key over a transient provider outage. Return a retryable 503
          // that says exactly that, and log LOUD with the real upstream cause
          // instead of ethers' misleading "reverted without a reason string".
          if (isChainReadFailure(e)) {
            const inner = e.error || {};
            console.error(
              `[connect] CHAIN READ FAILED — could NOT verify isAuthorized(${data.signerAddress}) ` +
                `on ${data.contractAddress}. Provider/RPC failure, NOT an authorization denial. ` +
                `code=${e.code} httpStatus=${inner.status ?? "?"} ` +
                `upstream=${inner.body || e.shortMessage || e.message}`,
            );
            return res.status(503).json({
              error:
                "Identity verification is temporarily unavailable — the chain could not be reached. This is not an authorization denial; retry shortly.",
              reason: "chain_unreachable",
              retryable: true,
            });
          }
          // Otherwise the call reached the chain and failed there (a real revert
          // or an unexpected execution error) — a genuine verification failure.
          console.error("[connect] Identity contract verification failed (on-chain):", e.message);
          return res.status(401).json({
            error: `Identity contract verification failed: ${e.message}`,
          });
        }
      }

      // Build the three-fact view we expose to downstream middleware AND
      // hand to any caller-supplied authentication() hook. identityAddress is
      // derived here; it never appears on the wire and is not stored.
      const clientInfo = {
        signerAddress: data.signerAddress,
        contractAddress: verifiedContractAddress,
        identityAddress: verifiedContractAddress || data.signerAddress,
        publicKey: data.signerPublicKey,
      };
      // Naming is a relay service (per-domain contract name + nicknames), not
      // epistery's concern — no name lookup here.
      if (epistery.options.authentication) {
        clientInfo.profile = await epistery.options.authentication.call(
          epistery.options.authentication,
          clientInfo,
        );
        clientInfo.authenticated = !!clientInfo.profile;
      }
      req.episteryClient = clientInfo;

      // Cookie stores facts only — signer + (verified) contract. identityAddress
      // is re-derived every read; persisting it would just be a place for the
      // two to drift apart.
      const sessionData = {
        signerAddress: data.signerAddress,
        contractAddress: verifiedContractAddress,
        publicKey: data.signerPublicKey,
        authenticated: clientInfo.authenticated || false,
        timestamp: new Date().toISOString(),
      };
      // The cookie holds one slot PER TAB, not one session for the origin, so
      // proving an identity here cannot displace what another tab already
      // proved. The tab names its slot with X-Epistery-Tab; a client that names
      // none gets the anonymous slot, which is also what a page load reads.
      // See session-jar.mjs.
      const sessionToken = jar.put(
        jar.cookieFromRequest(req),
        jar.tabFromRequest(req),
        sessionData,
      );

      // Cookie must be strictly scoped to this specific domain
      // Each domain has its own server wallet and client rivets in IndexedDB
      // DO NOT set domain attribute - let browser use strict same-origin policy
      res.cookie("_epistery", sessionToken, {
        httpOnly: true,
        secure: req.secure || req.headers["x-forwarded-proto"] === "https",
        sameSite: "strict",
        path: "/",
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      });

      // Call onAuthenticated hook if provided
      if (epistery.options.onAuthenticated && clientInfo.authenticated) {
        await epistery.options.onAuthenticated(clientInfo, req, res);
      }

      // The ORIGIN CERTIFICATE — the domain's countersignature on THIS device key.
      //
      // handleKeyExchange has already recovered data.signerAddress from the
      // client's own signature, so what the domain signs here is something it
      // verified rather than a claim it was handed. Until now the response signed
      // `Epistery Server Response - <serverAddress> - <challenge>`, which named
      // only itself: it proved the server held a key and bound nothing to the
      // device or the domain, leaving a third party nothing to check. That old
      // signature is still sent, so this is purely additive and an older client
      // keeps verifying exactly what it always did.
      //
      // The host comes from the REQUEST, and nothing is signed unless the loaded
      // domain config is for that same host. `epistery.domain` is one shared
      // instance mutated per request by the domain middleware, so a concurrent
      // request for another hostname can leave the two out of step. A certificate
      // naming the wrong domain would be a lie, which is worse than no
      // certificate, so this fails closed and logs which condition stopped it.
      let certificate = null;
      const certHost = req.hostname || req.headers.host?.split(":")[0] || null;
      if (!certHost) {
        console.warn("[connect] no host on the request — issuing no origin certificate");
      } else if (epistery.domainName !== certHost) {
        console.warn(
          `[connect] domain config is "${epistery.domainName}" but this request is for "${certHost}" — issuing no origin certificate`,
        );
      } else {
        try {
          certificate = await issueOriginCertificate(
            { rivet: data.signerAddress, domain: certHost },
            signer,
          );
        } catch (e) {
          console.warn(
            `[connect] could not issue an origin certificate for ${data.signerAddress}@${certHost}: ${e.message}`,
          );
        }
      }

      res.json(
        Object.assign(keyExchangeResponse, {
          profile: clientInfo.profile,
          authenticated: clientInfo.authenticated,
          certificate,
        }),
      );
    } catch (error) {
      console.error("Key exchange error:", error);
      res
        .status(500)
        .json({ error: "Internal server error during key exchange" });
    }
  });

  return router;
}
