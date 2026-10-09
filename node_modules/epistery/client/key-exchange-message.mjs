// The ONE definition of the key-exchange message a device signs to prove a key
// to a host (POST /connect) or to the config authority (/auth/verify): the bytes
// the signer signs are the bytes the verifier rebuilds. Was hand-built in five
// places; import it, never re-inline it. Pure ESM, browser- and Node-importable.
export function keyExchangeMessage({ address, challenge }) {
  return `Epistery Key Exchange - ${address} - ${challenge}`;
}

/**
 * The message a host signs to prove its identity back to the device: its own
 * address and the challenge it minted. Verified by the browser witness and the
 * CLI against the host's address; built by the host. One string, here.
 */
export function serverResponseMessage({ address, challenge }) {
  return `Epistery Server Response - ${address} - ${challenge}`;
}
