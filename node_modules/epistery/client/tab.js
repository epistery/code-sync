/*
 * Tab session — the per-TAB half of a rivet identity.
 *
 * A browser origin can hold many rivets (localStorage["epistery"].wallets).
 * Which one is ACTIVE used to be a single origin-wide fact, stated twice:
 *
 *   localStorage["epistery"].defaultWalletId   — the client's choice
 *   the _epistery session cookie               — the server's record of it
 *
 * Both are shared by every tab on the origin, so two tabs could never be two
 * different rivets. Switching in one tab switched them all, and the second
 * tab's key exchange overwrote the first tab's proven session underneath it.
 *
 * A tab is the natural unit of "who am I being right now", so the active rivet
 * belongs in TAB memory, not device memory:
 *
 *   sessionStorage["epistery.tab"]     this tab's id. Per-tab by construction,
 *                                      survives reload, dies with the tab.
 *   sessionStorage["epistery.wallet"]  the wallet id this tab is being.
 *   localStorage["epistery"].defaultWalletId
 *                                      the DEVICE default — what a brand new
 *                                      tab starts as. Last switch wins.
 *
 * Server side the tab id names one slot in the _epistery cookie's session jar
 * (routes/connect.mjs writes it, index.mjs reads it). A request says which slot
 * it means with the X-Epistery-Tab header, which installTabHeader() puts on
 * every same-origin fetch; a WebSocket, which cannot carry headers, says it
 * with ?_tab= instead. A request that names a slot the server does not hold
 * gets NO session and must re-handshake — it never silently falls back to
 * another tab's identity.
 *
 * Arming is deliberate and one-way. The header is sent only after this tab has
 * actually performed a key exchange (armTab, called from performKeyExchange).
 * Until then a request carries no tab header and the server answers from the
 * jar's default slot — exactly the pre-tab behaviour. So a page that never
 * handshakes, and an older server that knows nothing of slots, both keep
 * working unchanged.
 *
 * Two limits, stated plainly rather than papered over:
 *
 *   - A document navigation cannot carry a header, and a cookie cannot be
 *     scoped to a tab. The HTML request for a page therefore resolves against
 *     the jar's default slot. Tab identity covers the whole API surface (fetch,
 *     XHR, WebSocket); it does not cover the page load itself.
 *   - "Duplicate tab" copies sessionStorage, so the copy starts out sharing this
 *     tab's id and pin — one identity in two tabs, and a switch in either moves
 *     both. Separating them needs a live handshake between tabs, which is not
 *     worth it for a gesture the user rarely makes; opening a new tab normally
 *     gives a fresh, independent slot.
 */

const TAB_KEY = "epistery.tab";
const WALLET_KEY = "epistery.wallet";
export const TAB_HEADER = "X-Epistery-Tab";
export const TAB_PARAM = "_tab";

// sessionStorage is unavailable in some privacy modes. A memory fallback keeps
// the tab coherent for the life of the page; it just does not survive reload,
// which costs one extra key exchange and nothing else.
const mem = {};
function read(key) {
  try {
    const v = sessionStorage.getItem(key);
    if (v !== null) return v;
  } catch { /* fall through to memory */ }
  return mem[key] ?? null;
}
function write(key, value) {
  mem[key] = value;
  try { sessionStorage.setItem(key, value); } catch { /* memory only */ }
}
function drop(key) {
  delete mem[key];
  try { sessionStorage.removeItem(key); } catch { /* memory only */ }
}

// This tab's id, or null when the tab has not been armed. Null is the signal
// that means "I have no slot of my own — answer me from the default."
export function tabId() {
  return read(TAB_KEY);
}

// Mint this tab's id if it does not have one. Called immediately before a key
// exchange, so the id exists in time to ride the /connect request that creates
// the matching server-side slot.
export function armTab() {
  let id = read(TAB_KEY);
  if (!id) {
    const bytes = new Uint8Array(8);
    (globalThis.crypto || {}).getRandomValues?.(bytes);
    id = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    // No crypto (very old / non-secure context): still produce something unique
    // per tab. The id is a slot name, not a secret — the session it names was
    // proven by signature, and the cookie holding it is httpOnly.
    if (id === "0000000000000000") id = Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
    write(TAB_KEY, id);
  }
  return id;
}

// The wallet this tab is being, when it has said. Null means "use the device
// default" — an unswitched tab.
export function activeWalletId() {
  return read(WALLET_KEY);
}
export function pinWallet(walletId) {
  if (walletId) write(WALLET_KEY, walletId);
}
export function unpinWallet() {
  drop(WALLET_KEY);
}

// Add ?_tab= to a URL for transports that cannot carry a header (WebSocket).
// Returns the URL untouched while the tab is unarmed.
export function tabParam(url) {
  const id = tabId();
  if (!id) return url;
  return url + (url.includes("?") ? "&" : "?") + TAB_PARAM + "=" + encodeURIComponent(id);
}

// Put X-Epistery-Tab on every SAME-ORIGIN fetch, once the tab is armed.
//
// One shim rather than a header argument threaded through every call site: the
// rule "a request from this tab names this tab" is a property of the tab, not
// of any one caller, and there are hundreds of callers across the consumers.
// Cross-origin requests are left alone — the relay and other hosts authenticate
// by signature, not by this cookie, and adding a header there would only
// provoke CORS preflights.
export function installTabHeader() {
  if (typeof window === "undefined" || !window.fetch) return;
  if (window.fetch.__episteryTab) return;

  const native = window.fetch.bind(window);
  const shim = (input, init) => {
    const id = tabId();
    if (!id) return native(input, init);

    let url;
    try {
      url = new URL(typeof input === "string" ? input : input.url, location.href);
    } catch {
      return native(input, init);
    }
    if (url.origin !== location.origin) return native(input, init);

    // A Request argument carries its own headers. Rebuild it through the
    // Request(input, init) constructor — which merges init the way the spec
    // says — then set the header on the result, so nothing the caller passed
    // is lost or mutated.
    if (typeof input !== "string" && typeof Request !== "undefined" && input instanceof Request) {
      const req = new Request(input, init);
      req.headers.set(TAB_HEADER, id);
      return native(req);
    }
    const next = { ...(init || {}) };
    const headers = new Headers(next.headers || undefined);
    headers.set(TAB_HEADER, id);
    next.headers = headers;
    return native(input, next);
  };
  shim.__episteryTab = true;
  window.fetch = shim;
}
