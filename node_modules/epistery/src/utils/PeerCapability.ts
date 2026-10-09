import { ethers } from 'ethers';

/**
 * The capability surface a Node-side wallet shares with the browser wallets
 * (client/wallet.js): `canPeerEncrypt` and `computeSharedSecret`.
 *
 * Consumers — the TreeKEM leaf-decap seam above all — ask these two members and
 * never read `privateKey`. That is the seam where a key held in hardware
 * replaces the plaintext one in config.ini: it implements the same two members
 * (plus `signMessage`) and has no `privateKey` to hand out.
 */
export interface PeerCapable {
  readonly canPeerEncrypt: boolean;
  /** Raw ECDH shared secret (32-byte X) with a peer's uncompressed secp256k1
   *  public key — BEFORE any KDF, as the TreeKEM key schedule consumes it.
   *  `ethers` is accepted for signature parity with the browser wallets. */
  computeSharedSecret(peerPublicKey: string, ethers?: unknown): Promise<Uint8Array>;
}

/** The raw ECDH shared secret of an ethers Wallet with a peer's public key — the one body. */
export function sharedSecretOf(wallet: ethers.Wallet, peerPublicKey: string): Uint8Array {
  return ethers.utils.arrayify(wallet._signingKey().computeSharedSecret(peerPublicKey));
}

export function withPeerCapability<T extends ethers.Wallet>(wallet: T): T & PeerCapable {
  Object.defineProperty(wallet, 'canPeerEncrypt', { value: true, enumerable: true });
  Object.defineProperty(wallet, 'computeSharedSecret', {
    value: async (peerPublicKey: string) => sharedSecretOf(wallet, peerPublicKey),
  });
  return wallet as T & PeerCapable;
}
