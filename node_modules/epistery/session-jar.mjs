/*
 * Session jar — the _epistery cookie, which holds one proven session PER TAB.
 *
 * A cookie cannot be scoped to a tab, so a single session in a single cookie
 * made every tab on an origin one identity: the second tab's key exchange
 * overwrote the first tab's proven session underneath it. The cookie therefore
 * holds a small map of slots instead, and a request says which slot it means:
 *
 *   X-Epistery-Tab: <tab>   on fetch/XHR      (client/tab.js installs it)
 *   ?_tab=<tab>             on a WebSocket upgrade, which has no headers
 *
 * Rules, all of them deliberate:
 *
 *   - A request that NAMES a slot the jar does not hold resolves to NO session.
 *     It does not fall back to the default. Falling back is exactly the bug —
 *     it would hand a tab an identity it never proved. The tab re-handshakes.
 *   - A request that names NO slot resolves to the default slot: the one written
 *     by the most recent key exchange. This is the pre-tab behaviour, and it is
 *     what a document navigation gets, since a page load carries no header.
 *   - The jar is httpOnly and stays so. The entries are facts only — a proven
 *     signer plus a chain-verified contract — never a capability the client
 *     could mint for itself.
 *
 * Shape (short keys because a cookie has ~4KB to spend):
 *   { v: 2, def: "<tab>", s: { "<tab>": { signerAddress, contractAddress,
 *                                        publicKey, authenticated, timestamp } } }
 *
 * A pre-v2 cookie is a bare session object. decode() reads it as the anonymous
 * slot, so a browser holding one stays logged in across the upgrade.
 */

// Slot name for a client that sends no tab header: older libraries, a curl, a
// page that never handshakes. One named slot rather than a special case.
export const ANON_SLOT = "_";

// A cookie is capped near 4KB and browsers drop the whole thing when it is
// exceeded — a silent total logout. Bound the jar well under that and evict the
// oldest slot, so the cost of a tenth tab is the first tab re-handshaking, not
// every tab losing its session at once.
const MAX_SLOTS = 6;
const MAX_COOKIE_BYTES = 3500;

// Read the tab a request names, or null for "no slot named".
// Header first; the ?_tab= query is only for transports that cannot set one.
export function tabFromRequest(req) {
  const header = req?.headers?.["x-epistery-tab"];
  if (typeof header === "string" && header) return header;
  const url = req?.url || req?.originalUrl;
  if (typeof url === "string" && url.includes("_tab=")) {
    try {
      const q = new URL(url, "http://localhost").searchParams.get("_tab");
      if (q) return q;
    } catch { /* unparseable URL — no slot named */ }
  }
  return null;
}

// The raw _epistery cookie value, from the express-parsed jar when there is one
// and from the raw Cookie header otherwise (a WebSocket upgrade runs no
// middleware). One implementation so the two paths cannot drift.
export function cookieFromRequest(req) {
  const parsed = req?.cookies?._epistery;
  if (parsed) return parsed;
  const header = req?.headers?.cookie;
  if (!header) return null;
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    if (trimmed.slice(0, eq) !== "_epistery") continue;
    return decodeURIComponent(trimmed.slice(eq + 1));
  }
  return null;
}

// base64 cookie value -> { def, s } — or null when there is nothing readable.
export function decode(cookieValue) {
  if (!cookieValue) return null;
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(cookieValue, "base64").toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;

  if (parsed.s && typeof parsed.s === "object") {
    return { def: parsed.def || ANON_SLOT, s: parsed.s };
  }
  // Pre-v2: the cookie WAS the session. Read it as the anonymous slot.
  if (parsed.signerAddress) {
    return { def: ANON_SLOT, s: { [ANON_SLOT]: parsed } };
  }
  return null;
}

export function encode(jar) {
  return Buffer.from(JSON.stringify({ v: 2, def: jar.def, s: jar.s })).toString("base64");
}

// The session a request is entitled to, or null. `tab` is what the request
// named (null for "nothing named") — see the rules at the top of this file.
export function select(jar, tab) {
  if (!jar) return null;
  if (tab) return jar.s[tab] || null;
  return jar.s[jar.def] || null;
}

// Put `session` in `tab`'s slot and make it the default, then trim to fit.
// Returns the new base64 cookie value.
export function put(cookieValue, tab, session) {
  const jar = decode(cookieValue) || { def: ANON_SLOT, s: {} };
  const slot = tab || ANON_SLOT;
  jar.s[slot] = session;
  jar.def = slot;

  // Evict oldest-first, never the slot we just wrote.
  const age = (id) => Date.parse(jar.s[id]?.timestamp || "") || 0;
  const others = () =>
    Object.keys(jar.s)
      .filter((id) => id !== slot)
      .sort((a, b) => age(a) - age(b));

  while (Object.keys(jar.s).length > MAX_SLOTS) {
    const oldest = others()[0];
    if (!oldest) break;
    delete jar.s[oldest];
  }
  let value = encode(jar);
  while (value.length > MAX_COOKIE_BYTES) {
    const oldest = others()[0];
    if (!oldest) break;
    delete jar.s[oldest];
    value = encode(jar);
  }
  return value;
}
