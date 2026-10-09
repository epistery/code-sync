// The ONE definition of the epistery origin certificate — the domain's
// countersignature on a device key.
//
// A browser rivet's key is origin-scoped: it can only ever sign from the origin
// that minted it. But a domain NAME inside a message signed by page JS is
// self-asserted — a commitment, not proof. This is the proof: at key exchange the
// domain's own wallet signs {rivet, domain, ts}, so the device can afterwards
// present, to anyone, a statement BY the domain that it saw this rivet prove
// control of its key at that moment.
//
// The chain of proof this completes:
//   the rivet's own signature  binds event  → device
//   THIS certificate           binds device → domain
//   the signed /.well-known/ai binds domain → chain identity
//
// What it replaces: the key-exchange response signed `Epistery Server Response -
// <serverAddress> - <challenge>`, a statement naming only itself. That proved the
// server held a key and bound nothing to the device or the domain, so a third
// party had nothing to check. The old signature is still sent alongside this one
// — this is additive, so an old client keeps verifying what it always did.
//
// Mirrors storage-message.mjs and bot-auth-message.mjs: one definition, imported,
// never re-inlined. Pure ESM, zero dependencies, no Node-only APIs, so the
// identical module loads in a Node server and in a browser. `ethers` is passed in
// where it is needed, following the convention in client/wallet.js.
//
// Wire shape: five lines joined by '\n', in this fixed order. Verifiers split on
// '\n' and require exactly length 5 with line 0 === the tag. Changing the order,
// the count, or the tag is a wire-breaking change for every signer and verifier
// at once — which is the intent. An old signer must fail outright rather than
// degrade into a certificate that means something subtly different.
//
//   0  'epistery-origin-certificate'  tag
//   1  v                              envelope version ('1')
//   2  rivet                          the device address, lowercase hex
//   3  domain                         the host that countersigned, lowercase, no port
//   4  ts                             unix milliseconds the domain signed it

export const ORIGIN_CERT_TAG = 'epistery-origin-certificate';
export const ORIGIN_CERT_VERSION = '1';

// How long a certificate is honoured, defined HERE rather than guessed by each
// verifier. A certificate attests that a device proved control at a moment; it is
// not a session and must not become one. A day is long enough that a normal
// browsing session never re-handshakes just to refresh it, and short enough that
// a copied certificate stops working while the device it names is still in use.
// A verifier that wants a tighter window passes its own maxAgeMs explicitly.
export const ORIGIN_CERT_MAX_AGE_MS = 24 * 60 * 60 * 1000;

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

// Both fields are normalized before they enter the bytes, so a checksummed
// address and a lowercase one produce the SAME certificate and a verifier never
// has to guess which casing the signer used.
function normAddress(value, label) {
  const s = String(value ?? '').trim();
  if (!ADDRESS_RE.test(s)) throw new Error(`origin-certificate: ${label} must be a 0x-prefixed 40-hex address`);
  return s.toLowerCase();
}

// The host only — no scheme, no port, no trailing dot. A certificate names the
// host the browser actually talked to, which is the origin its key is bound to.
function normDomain(value) {
  const s = String(value ?? '').trim().toLowerCase().replace(/\.$/, '').split(':')[0];
  if (!s) throw new Error('origin-certificate: domain is required');
  return s;
}

function normTs(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) throw new Error('origin-certificate: ts must be a positive unix-millisecond value');
  return Math.floor(n);
}

/** The exact bytes a domain signs to countersign one device key. */
export function originCertificateMessage({ rivet, domain, ts }) {
  return [
    ORIGIN_CERT_TAG,
    ORIGIN_CERT_VERSION,
    normAddress(rivet, 'rivet'),
    normDomain(domain),
    String(normTs(ts)),
  ].join('\n');
}

/**
 * Issue a certificate. Called by the domain at key exchange, with the domain's
 * OWN wallet — never a pool, a relay, or any wallet that speaks for someone else.
 * The rivet passed here must already have proved control of its key in the same
 * exchange; this signs what the domain observed, and observing is the whole claim.
 *
 * @param {{rivet:string, domain:string, ts?:number}} claim
 * @param {{signMessage:(m:string)=>Promise<string>}} domainWallet  ethers Wallet or equivalent
 * @returns {Promise<{v:string, rivet:string, domain:string, ts:number, signature:string}>}
 */
export async function issueOriginCertificate({ rivet, domain, ts = Date.now() }, domainWallet) {
  if (!domainWallet?.signMessage) throw new Error('origin-certificate: a signing wallet is required');
  const claim = { rivet: normAddress(rivet, 'rivet'), domain: normDomain(domain), ts: normTs(ts) };
  const signature = await domainWallet.signMessage(originCertificateMessage(claim));
  return { v: ORIGIN_CERT_VERSION, ...claim, signature };
}

/**
 * Verify a presented certificate. Returns a typed result rather than throwing, so
 * a caller can tell "no certificate" from "a certificate that does not hold" and
 * act differently — the distinction that matters when an older peer simply has
 * none to present.
 *
 * `expectDomainWallet` is the address the domain publishes as its own. Resolve it
 * from that domain, never from the presenter: a certificate checked against an
 * address the presenter supplied proves nothing at all.
 *
 * @returns {{ok:boolean, reason?:string, signer?:string}}
 */
export function verifyOriginCertificate(cert, { domain, rivet, expectDomainWallet, now = Date.now(), maxAgeMs = ORIGIN_CERT_MAX_AGE_MS } = {}, ethers) {
  if (!cert) return { ok: false, reason: 'absent' };
  if (!ethers?.utils?.verifyMessage) return { ok: false, reason: 'no ethers provided to verify with' };
  if (cert.v !== ORIGIN_CERT_VERSION) return { ok: false, reason: `unsupported certificate version "${cert.v}"` };
  if (!expectDomainWallet) return { ok: false, reason: 'no published domain wallet to check against' };

  let message, claimed;
  try {
    claimed = { rivet: normAddress(cert.rivet, 'rivet'), domain: normDomain(cert.domain), ts: normTs(cert.ts) };
    message = originCertificateMessage(claimed);
  } catch (e) {
    return { ok: false, reason: e.message };
  }

  // The certificate must be about the device and the domain the caller is
  // actually asking about. Skipping either check turns any valid certificate into
  // a universal one.
  if (rivet && claimed.rivet !== normAddress(rivet, 'rivet')) return { ok: false, reason: 'certificate names a different rivet' };
  if (domain && claimed.domain !== normDomain(domain)) return { ok: false, reason: 'certificate names a different domain' };

  const age = now - claimed.ts;
  if (age > maxAgeMs) return { ok: false, reason: `certificate is stale (${Math.round(age / 1000)}s old)` };
  // A future timestamp is not a clock to be tolerated, it is a claim about an
  // observation that has not happened. One minute absorbs ordinary skew.
  if (age < -60_000) return { ok: false, reason: 'certificate is dated in the future' };

  let signer;
  try {
    signer = ethers.utils.verifyMessage(message, cert.signature);
  } catch (e) {
    return { ok: false, reason: `signature does not recover: ${e.message}` };
  }
  if (signer.toLowerCase() !== String(expectDomainWallet).toLowerCase()) {
    return { ok: false, reason: `signed by ${signer}, not the domain wallet ${expectDomainWallet}` };
  }
  return { ok: true, signer };
}
