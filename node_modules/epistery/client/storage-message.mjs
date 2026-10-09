// The ONE definition of the epistery /storage signed-write WIRE: the six-line
// message, the `Bot <base64url json>` credential that carries it, the parser
// that reads it back, the body hash it commits to, and the address shape it
// names. Core owns the wire (EpisteryRefactor3Q26Review §9, decision 3) and no
// UI; every signer and every verifier imports this module, none re-inlines it.
//
// Historically the message string was copied into three places and the
// credential envelope was built four times and parsed twice, each copy carrying
// a "MUST match the others EXACTLY" comment — precisely the byte-drift hazard
// that comment admits. This module is that single home.
//
// Pure ESM, zero dependencies, no Node-only APIs — the identical module imports
// in a Node server and in a browser (served as a static asset). Hashing uses
// WebCrypto (globalThis.crypto.subtle), present in every browser and in Node.
//
// Wire shape of the message: six lines joined by '\n', in this fixed order. A
// verifier splits on '\n' and requires exactly length 6 with line 0 ===
// 'epistery-storage-write'. Changing the order, the count, or the tag is a
// wire-breaking change for every signer and verifier at once.
//
// Wire shape of the credential: base64url (no padding) of the JSON object
// {address, signature, message[, identity]} with the keys in THAT order and
// `identity` present only when given — so the bytes a signer produces are the
// bytes a verifier hashes, byte for byte, in Node (Buffer.from(json).toString(
// 'base64url')) and in the browser alike. It travels as `Authorization: Bot
// <credential>`, and a DS commit keeps the bare credential beside the commit.

export const STORAGE_WRITE_TAG = 'epistery-storage-write';

/** The signed bytes of one storage write. */
export function storageWriteMessage({ method, contract, subpath, bodyHashHex, ts }) {
  return [STORAGE_WRITE_TAG, method, contract, subpath, bodyHashHex, String(ts)].join('\n');
}

/**
 * Read a signed message back into its fields. Returns null for anything that is
 * not exactly a storage-write message (wrong line count, wrong tag, non-numeric
 * ts) — a verifier then refuses, it never guesses.
 */
export function parseStorageWriteMessage(message) {
  if (typeof message !== 'string') return null;
  const lines = message.split('\n');
  if (lines.length !== 6 || lines[0] !== STORAGE_WRITE_TAG) return null;
  const ts = Number(lines[5]);
  if (!Number.isFinite(ts)) return null;
  return { method: lines[1], contract: lines[2], subpath: lines[3], bodyHashHex: lines[4], ts };
}

/** An EVM address: 0x + 40 hex digits, either case. The one regex. */
export const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
export function isAddress(value) {
  return typeof value === 'string' && ADDRESS_RE.test(value);
}

// base64url without padding, over UTF-8 bytes. btoa/atob and TextEncoder exist in
// browsers and in Node (v16+), so no Buffer is needed for the same bytes.
const utf8 = new TextEncoder();
const utf8d = new TextDecoder();
export function base64urlEncode(bytes) {
  const u = typeof bytes === 'string' ? utf8.encode(bytes) : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function base64urlDecode(text) {
  let b = String(text || '').replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  const bin = atob(b);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

/**
 * The credential a signer sends: base64url of {address, signature, message[,
 * identity]}. `identity` is the contract (or address) the signer acts as; it is
 * written only when given, so a credential without one is byte-identical to the
 * historical three-field form.
 */
export function encodeStorageCredential({ address, signature, message, identity }) {
  const fields = identity ? { address, signature, message, identity } : { address, signature, message };
  return base64urlEncode(JSON.stringify(fields));
}

/**
 * Read a credential back. Returns {address, signature, message, identity|null}
 * when the bytes decode to an object naming an address, a signature and a
 * message; otherwise null. Accepts the bare credential or the full
 * `Bot <credential>` header value. Verifying the signature is the caller's
 * job (it needs ethers); this only reads.
 */
export function decodeStorageCredential(value) {
  if (typeof value !== 'string') return null;
  const bare = value.startsWith('Bot ') ? value.slice(4) : value;
  let c;
  try { c = JSON.parse(utf8d.decode(base64urlDecode(bare))); } catch { return null; }
  if (!c || typeof c !== 'object') return null;
  if (!isAddress(c.address) || typeof c.signature !== 'string' || typeof c.message !== 'string') return null;
  return { address: c.address, signature: c.signature, message: c.message, identity: isAddress(c.identity) ? c.identity : null };
}

/** The header value: `Bot <credential>`. */
export function storageAuthorization(credential) {
  return `Bot ${credential}`;
}

/**
 * Build a signed credential for one write. `sign(message)` returns the
 * signature from whatever holds the key — an ethers Wallet's signMessage, a
 * browser rivet's sign — so this module never touches key material. `address`
 * is the signer the verifier will recover; `identity` (optional) is the
 * contract the signer acts as. Returns {message, credential, authorization}.
 */
export async function signStorageWrite({ sign, address, identity = null, method, contract, subpath, bodyHashHex, ts = Date.now() }) {
  const message = storageWriteMessage({ method, contract, subpath, bodyHashHex, ts });
  const signature = await sign(message);
  const credential = encodeStorageCredential({ address, signature, message, identity });
  return { message, credential, authorization: storageAuthorization(credential) };
}

/**
 * SHA-256 of a body as lowercase hex — the one `bodyHashHex`. Accepts bytes
 * (Uint8Array/ArrayBuffer) or a string (UTF-8). Async because WebCrypto is; a
 * Node caller awaits it exactly as a browser does.
 */
export async function sha256hex(data) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('sha256hex: WebCrypto (globalThis.crypto.subtle) is required');
  const bytes = typeof data === 'string' ? utf8.encode(data) : new Uint8Array(data);
  const digest = new Uint8Array(await subtle.digest('SHA-256', bytes));
  let hex = '';
  for (let i = 0; i < digest.length; i++) hex += digest[i].toString(16).padStart(2, '0');
  return hex;
}
