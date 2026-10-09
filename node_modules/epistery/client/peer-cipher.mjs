// The ONE peer-encryption and content-encryption construction. Core owns the wire
// (EpisteryRefactor3Q26Review, decision 3): what a wrap and a sealed record ARE
// is defined here and nowhere else.
//
//   wrap     ECDH(secp256k1) shared X → SHA-256 → AES-256-GCM, 12-byte iv,
//            recorded as { ciphertext, iv, tag } with the 16-byte tag SPLIT OFF
//   content  AES-256-GCM under a 32-byte key K, 12-byte iv, recorded as
//            { iv, ciphertext } with the tag APPENDED (WebCrypto's native output)
//
// Both layouts are what every stored wrap and sealed record already carries
// (the browser cipher, the server twin and the rivet's own primitive agreed
// byte for byte; the test freezes vectors from the server twin). Nothing here
// derives keys any other way, so there is no second key channel.
//
// Pure ESM on WebCrypto — one module for the browser and for Node. ECDH itself
// is ethers' SigningKey, passed in: a rivet whose key never leaves WebCrypto
// computes the shared secret through its own capability and hands the bytes
// here; a plain ethers Wallet computes it from its private key.

const subtle = () => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('peer-cipher: WebCrypto (globalThis.crypto.subtle) is required');
  return s;
};
const random = (n) => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; };

export const toHex = (u8) => { let s = '0x'; for (const b of u8) s += b.toString(16).padStart(2, '0'); return s; };
export const fromHex = (hex) => {
  const h = String(hex).startsWith('0x') ? String(hex).slice(2) : String(hex);
  if (h.length % 2) throw new Error('peer-cipher: odd-length hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};
const bytesOf = (v) => (v instanceof Uint8Array ? v : typeof v === 'string' ? fromHex(v) : new Uint8Array(v));

/** A random 32-byte key, 0x-hex — a session key, a message key, a document key. */
export function randomKey() { return toHex(random(32)); }

/** The raw ECDH shared secret (32-byte X) for a private key and a peer's public key. */
export function ecdhShared(privateKeyHex, peerPublicKeyHex, ethers = globalThis.ethers) {
  if (!ethers?.utils?.SigningKey) throw new Error('peer-cipher: ethers v5 is required for ECDH');
  return fromHex(new ethers.utils.SigningKey(privateKeyHex).computeSharedSecret(peerPublicKeyHex));
}

/** SHA-256 of the shared secret, imported as the AES-256-GCM key. */
export async function aesKeyFromShared(sharedBytes) {
  const material = await subtle().digest('SHA-256', bytesOf(sharedBytes));
  return subtle().importKey('raw', material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Seal bytes under an AES key: { ciphertext, iv, tag } as bytes, tag split off. */
export async function sealWithKey(aesKey, plaintextBytes) {
  const iv = random(12);
  const ctTag = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, aesKey, bytesOf(plaintextBytes)));
  return { ciphertext: ctTag.slice(0, -16), iv, tag: ctTag.slice(-16) };
}

/** Open { ciphertext, iv, tag } bytes under an AES key → plaintext bytes. */
export async function openWithKey(aesKey, ciphertextBytes, ivBytes, tagBytes) {
  const ct = bytesOf(ciphertextBytes), tag = bytesOf(tagBytes);
  const ctTag = new Uint8Array(ct.length + tag.length); ctTag.set(ct, 0); ctTag.set(tag, ct.length);
  return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: bytesOf(ivBytes), tagLength: 128 }, aesKey, ctTag));
}

/** Seal bytes to a peer from a shared secret: { ciphertext, iv, tag } as bytes. */
export async function sealWithShared(sharedBytes, plaintextBytes) {
  return sealWithKey(await aesKeyFromShared(sharedBytes), plaintextBytes);
}
/** Open a peer wrap from a shared secret → plaintext bytes. */
export async function openWithShared(sharedBytes, ciphertextBytes, ivBytes, tagBytes) {
  return openWithKey(await aesKeyFromShared(sharedBytes), ciphertextBytes, ivBytes, tagBytes);
}

// ---- wraps by capability -------------------------------------------------------
//
// A wallet is asked, never opened (EpisteryCore: capability over source). A rivet
// exposes encryptForPeer/decryptFromPeer (its key stays in WebCrypto); a plain
// ethers Wallet exposes privateKey; either wraps the same bytes.

/** Wrap a key K (0x-hex) to a peer's public key: { ciphertext, iv, tag } as 0x-hex. */
export async function wrapKey(K, peerPublicKey, wallet, ethers = globalThis.ethers) {
  const keyBytes = fromHex(K);
  let r;
  if (typeof wallet?.encryptForPeer === 'function') r = await wallet.encryptForPeer(peerPublicKey, keyBytes, ethers);
  else if (wallet?.privateKey) r = await sealWithShared(ecdhShared(wallet.privateKey, peerPublicKey, ethers), keyBytes);
  else throw new Error('peer-cipher: this wallet can neither encrypt for a peer nor expose a key');
  return { ciphertext: toHex(bytesOf(r.ciphertext)), iv: toHex(bytesOf(r.iv)), tag: toHex(bytesOf(r.tag)) };
}

/** Unwrap { ciphertext, iv, tag } (0x-hex) wrapped by `wrapperPublicKey` → K as 0x-hex. */
export async function unwrapKey(wrap, wrapperPublicKey, wallet, ethers = globalThis.ethers) {
  const ct = fromHex(wrap.ciphertext), iv = fromHex(wrap.iv), tag = fromHex(wrap.tag);
  let bytes;
  if (typeof wallet?.decryptFromPeer === 'function') bytes = await wallet.decryptFromPeer(wrapperPublicKey, ct, iv, tag, ethers);
  else if (wallet?.privateKey) bytes = await openWithShared(ecdhShared(wallet.privateKey, wrapperPublicKey, ethers), ct, iv, tag);
  else throw new Error('peer-cipher: this wallet can neither decrypt from a peer nor expose a key');
  return toHex(bytesOf(bytes));
}

// ---- content under K -----------------------------------------------------------

async function importK(K) {
  return subtle().importKey('raw', bytesOf(K), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Encrypt bytes under K: { iv: 0x-hex, ciphertext: bytes (ct‖tag) }. */
export async function encryptBytes(K, plaintextBytes) {
  const iv = random(12);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, await importK(K), bytesOf(plaintextBytes)));
  return { iv: toHex(iv), ciphertext: ct };
}
/** Decrypt ct‖tag bytes under K with the record's iv → plaintext bytes. */
export async function decryptBytes(K, iv, ciphertextBytes) {
  return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: bytesOf(iv), tagLength: 128 }, await importK(K), bytesOf(ciphertextBytes)));
}

/** Encrypt UTF-8 text under K: { iv, ciphertext } as 0x-hex — the sealed-record shape. */
export async function encryptText(K, text) {
  const { iv, ciphertext } = await encryptBytes(K, new TextEncoder().encode(String(text)));
  return { iv, ciphertext: toHex(ciphertext) };
}
/** Decrypt { iv, ciphertext } (0x-hex) under K → text. */
export async function decryptText(K, blob) {
  return new TextDecoder().decode(await decryptBytes(K, blob.iv, fromHex(blob.ciphertext)));
}
