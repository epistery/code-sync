// Chain reads a caller makes itself (EpisteryChainReads, Proposal A).
// Browser-servable and Node-importable, like storage-message.mjs: it takes ethers
// v5 from the caller or from globalThis.
//
// Two things live here:
//
//   isChainReadFailure(e) — did the read FAIL, or did the chain ANSWER? A failed
//     read means "ask again"; a false or a revert means "no". Conflating them is
//     what let a provider outage read as a rejection (connect.mjs, PR #37, which
//     now imports it from here).
//
//   chainReader({ rpcs, quorum, chainId }) — ATTESTATION reads: facts a caller acts
//     on as verified (who may seat a device in a group, who may write, whether an
//     address holds code, any view a caller names). `rpcs` are the chain's
//     attestation endpoints — OWNED nodes only (attestationConfig() in the chain
//     registry, which also supplies `quorum`). An answer is asserted k-of-n, like a
//     multisig: it stands when `quorum` nodes give it (default a majority — 1 of 1,
//     2 of 3), so one jammed node neither blocks the read nor decides it. Otherwise
//     the read is refused — CHAIN_DISAGREES or CHAIN_UNREACHABLE — never guessed,
//     and never answered by a foreign gateway. Today the operator runs the only
//     node; each independent node added is one more that a lie must get past.
//     A node answers only while its head is FRESH: before its answer counts, its
//     latest block must be younger than `maxHeadAgeMs` (2 minutes; Polygon seals a
//     block every 2 seconds). A node whose chain has stopped answers every read
//     confidently from an old world — balances, roles, seats, all hours out of
//     date and all "correct" by its own book — and at quorum 1 that is the whole
//     answer. Stale is a non-answer, like down: the read is refused, never served
//     from the past. (2026-10-01: an owned node sat 3.5 hours behind a hardfork
//     while every console balance read it as current.)
//
// The rules are the relay's storage-auth rules (the relay still implements them
// separately), so a member and the relay reach the same verdict from the same chain:
//   rivet : isAuthorized(addr) on the contract, or — an identity admitted as a
//           signer vouching for its own rivet — any contract in getRivets() whose
//           isAuthorized(addr) is true
//   role  : roleOf(section, addr); an identity that vouches for addr lends it its
//           own role (the credential's `identity`)

// A revert is an answer of nothing, however the node reports it. A node that
// reports a revert as a JSON-RPC error reaches ethers as a CALL_EXCEPTION with
// its bytes (classified below as an answer, not a failure). A node that returns
// the same bytes as the call's RESULT reaches us as a string — Error(string) or
// Panic(uint256) bytes that decodeFunctionResult would then throw on, as if the
// chain had failed to answer. Both are the one thing: the contract reverted.
const REVERT_SELECTORS = ["0x08c379a0", "0x4e487b71"];   // Error(string), Panic(uint256)
const isRevertPayload = (out) => typeof out === "string" && REVERT_SELECTORS.includes(out.slice(0, 10).toLowerCase());

// ethers v5 pitfall: when an endpoint returns a non-result (an HTTP 403, a rate
// limit) ethers does not surface a transport error for an eth_call — it fabricates
// a CALL_EXCEPTION with data "0x", indistinguishable at a glance from a revert. That
// shape (no revert bytes, and/or a transport error nested in e.error) is a read
// failure, not an answer.
export function isChainReadFailure(e) {
  if (!e) return false;
  if (e.code === "SERVER_ERROR" || e.code === "TIMEOUT" || e.code === "NETWORK_ERROR") {
    return true;
  }
  if (e.code === "CALL_EXCEPTION") {
    const noRevertData = e.data == null || e.data === "0x";
    const inner = e.error || {};
    const transportUnderneath =
      inner.code === "SERVER_ERROR" ||
      inner.code === "TIMEOUT" ||
      inner.code === "NETWORK_ERROR" ||
      typeof inner.status === "number";
    if (noRevertData || transportUnderneath) return true;
  }
  return false;
}

const ABI = [
  "function isAuthorized(address) view returns (bool)",
  "function getRivets() view returns (address[])",
  "function roleOf(string section, address account) view returns (uint8)",
];
// The EpisteryAccess role table — the values the contract stores (contracts/
// EpisteryAccess.sol: ROLE_NONE..ROLE_OWNER). The one declaration; every
// verifier, client and UI that names a role imports it from here.
export const ROLE = Object.freeze({ NONE: 0, READ: 1, WRITE: 2, ADMIN: 3, OWNER: 4 });
export const ROLE_NAME = Object.freeze({ 0: 'none', 1: 'read', 2: 'write', 3: 'admin', 4: 'owner' });
export function roleName(role) { return ROLE_NAME[Number(role)] ?? null; }
const lc = (a) => String(a || "").toLowerCase();
const host = (url) => { try { return new URL(url).host; } catch { return String(url); } };

export function chainReader({ rpcs, quorum = null, chainId, ethers = globalThis.ethers, ttlMs = 10 * 60 * 1000, timeoutMs = 15000, maxHeadAgeMs = 2 * 60 * 1000, headTtlMs = 15000, observe = null } = {}) {
  const endpoints = [...new Set((rpcs || []).filter(Boolean))];
  if (!endpoints.length) {
    throw new Error("chainReader: no attestation endpoint — an attestation read is answered by an owned node or not at all");
  }
  if (!ethers?.providers) throw new Error("chainReader: ethers v5 is required");
  // Unset: a majority of the configured nodes (1 of 1, 2 of 3). A host may be
  // stricter or looser; outside 1..n is a misconfiguration.
  quorum = quorum == null ? Math.floor(endpoints.length / 2) + 1 : Number(quorum);
  if (!Number.isInteger(quorum) || quorum < 1 || quorum > endpoints.length) {
    throw new Error(`chainReader: quorum ${quorum} is not between 1 and the ${endpoints.length} configured node(s)`);
  }
  if (!(Number(maxHeadAgeMs) > 0)) throw new Error("chainReader: maxHeadAgeMs must be a positive number of milliseconds — a node's head is fresh or the node is not an answer");
  const network = chainId ? Number(chainId) : undefined;
  const providers = endpoints.map((url) => ({ url, provider: new ethers.providers.StaticJsonRpcProvider(url, network), head: null }));

  // Is this node's head fresh? Its latest block's timestamp against the clock,
  // asked at most once per `headTtlMs` so a burst of reads costs one block fetch.
  // A head older than `maxHeadAgeMs`, or no head at all, makes the node a
  // non-answer for every read until it catches up — tagged CHAIN_STALE so the
  // refusal says which node and how far behind.
  function assertFresh(node) {
    const now = Date.now();
    if (node.head && now - node.head.at < headTtlMs) return node.head.verdict;
    const verdict = node.provider.send("eth_getBlockByNumber", ["latest", false]).then((b) => {
      const ts = b && b.timestamp != null ? Number(b.timestamp) * 1000 : NaN;
      if (!Number.isFinite(ts)) throw stale(node, "reports no head block");
      const ageMs = Date.now() - ts;
      if (ageMs > maxHeadAgeMs) throw stale(node, `is stale: head #${Number(b.number)} is ${Math.round(ageMs / 1000)}s old, ${Math.round(maxHeadAgeMs / 1000)}s allowed`);
    });
    node.head = { at: now, verdict };
    return verdict;
  }
  const stale = (node, why) => { const e = new Error(`${host(node.url)} ${why}`); e.code = "CHAIN_STALE"; return e; };
  const iface = new ethers.utils.Interface(ABI);
  const ifaces = new Map();   // abi text → Interface, for view()
  const cache = new Map();
  // Where a refusal is born is where it is reported: `observe` hears every read
  // settle — `{ ok: true }` or `{ ok: false, code, message }` — so a host can
  // make a refusal SEEN (an alarm in its own messaging) rather than only thrown
  // at whoever asked. It can neither change nor delay the read.
  const report = (event) => { if (typeof observe === "function") { try { observe(event); } catch { /* an observer's fault is its own */ } } };

  // One read, asserted k-of-n like a multisig: every node is asked at once, and an
  // answer stands when `quorum` nodes give it. The read settles the moment the
  // outcome is decided, so a jammed node — one that hangs, errors, or lies — cannot
  // hold it hostage while enough others agree. Refused, never guessed:
  //   CHAIN_DISAGREES   two different answers both reached the quorum (only possible
  //                     with a quorum at or below half), or too many answers differ
  //                     for any to reach it
  //   CHAIN_UNREACHABLE too few nodes answered at all
  // `ask(provider)` performs the read on one node and resolves to its answer: a
  // string, or null when the chain answered "nothing" (a revert with its reason, no
  // contract at the address, no code). A failed read (isChainReadFailure) is a
  // non-answer, never a "no".
  function agree(ask) {
    return new Promise((resolve, reject) => {
      const votes = new Map();   // answer → count
      const failures = [];
      let pending = providers.length, done = false;
      const refuse = (code, msg) => { const e = new Error(msg); e.code = code; done = true; clearTimeout(timer); report({ ok: false, code, message: msg }); reject(e); };
      const decide = () => {
        if (done) return;
        const reached = [...votes].filter(([, n]) => n >= quorum);
        if (reached.length > 1) return refuse("CHAIN_DISAGREES", `chain nodes disagree, and more than one answer reached ${quorum} of ${providers.length} — refusing rather than choosing`);
        // Decided once one answer has the quorum and no other answer — one already
        // given, or one from a node not yet heard — can still reach it.
        if (reached.length === 1 && pending < quorum && [...votes].every(([v, n]) => v === reached[0][0] || n + pending < quorum)) {
          done = true; clearTimeout(timer); report({ ok: true }); return resolve(reached[0][0] === "null" ? null : reached[0][0]);
        }
        const best = Math.max(0, ...votes.values());
        if (best + pending >= quorum) return;   // still possible
        const answered = [...votes.values()].reduce((a, n) => a + n, 0);
        if (answered + pending < quorum) return refuse("CHAIN_UNREACHABLE", `${answered} of ${providers.length} chain nodes answered, ${quorum} needed (${failures.join("; ") || "no answer in time"})`);
        return refuse("CHAIN_DISAGREES", `chain nodes disagree — no answer reached ${quorum} of ${providers.length}`);
      };
      const timer = setTimeout(() => { if (!done) { pending = 0; failures.push(`no answer within ${timeoutMs}ms`); decide(); } }, timeoutMs);
      for (const node of providers) {
        const { url, provider } = node;
        Promise.resolve().then(() => assertFresh(node)).then(() => ask(provider)).then(
          (out) => ({ answer: out == null || out === "0x" || isRevertPayload(out) ? null : String(out) }),
          (e) => (e?.code === "CHAIN_STALE" ? { failure: e.message }
            : isChainReadFailure(e) ? { failure: `${host(url)} ${e.reason || e.code}` } : { answer: null }),   // a revert is an answer: no
        ).then((o) => {
          if (done) return;
          pending -= 1;
          if ("failure" in o) failures.push(o.failure);
          else { const k = String(o.answer).toLowerCase(); votes.set(k, (votes.get(k) || 0) + 1); }
          decide();
        });
      }
    });
  }
  const call = (to, data) => agree((p) => p.call({ to, data }));
  async function read(to, fn, args) {
    const out = await call(to, iface.encodeFunctionData(fn, args));
    if (out == null) return null;
    return iface.decodeFunctionResult(fn, out)[0];
  }
  // `fresh` skips the cache for one read — what a caller that just acted passes so
  // it does not wait out the TTL to see its own grant.
  const cached = async (key, compute, fresh = false) => {
    const hit = fresh ? null : cache.get(key);
    if (hit && Date.now() - hit.at < ttlMs) return hit.value;
    const value = await compute();
    cache.set(key, { at: Date.now(), value });
    return value;
  };

  // Any view a caller names, by its ABI fragment(s): the k-of-n read for facts the
  // fixed verbs below do not cover (section names, an ACL, a public attribute).
  // null when the chain answers nothing — no contract there, no such function, a
  // revert. One output is returned bare; several as the decoded result.
  async function view(to, abi, fn, args = [], { fresh = false } = {}) {
    // Fragments may be human-readable strings or JSON ABI objects; the key must
    // tell two JSON ABIs apart, which String() would not.
    const fragments = Array.isArray(abi) ? abi : [abi];
    const text = fragments.map((f) => (typeof f === "string" ? f : JSON.stringify(f))).join("\n");
    let vi = ifaces.get(text);
    if (!vi) { vi = new ethers.utils.Interface(fragments); ifaces.set(text, vi); }
    return cached(`view|${lc(to)}|${fn}|${JSON.stringify(args)}`, async () => {
      const out = await call(to, vi.encodeFunctionData(fn, args));
      if (out == null) return null;
      const res = vi.decodeFunctionResult(fn, out);
      return res.length === 1 ? res[0] : res;
    }, fresh);
  }

  // Does an address hold code? The probe that precedes "is this an IdentityContract"
  // (decision 1): with the one classifier a bare CALL_EXCEPTION is a failed read, so
  // "not a contract" has to be established by this read, never inferred from a call
  // that did not answer.
  async function hasCode(to, { fresh = false } = {}) {
    return cached(`code|${lc(to)}`, async () => (await agree((p) => p.getCode(to))) != null, fresh);
  }

  // The native balance of an address, as the attested chain holds it. Never
  // cached: a balance is the one fact a caller reads expecting it to have just
  // changed (its own transfer landing), so each read goes to the nodes — the
  // head check (15 s) is the only reuse. Returns an ethers BigNumber.
  async function balanceOf(addr) {
    const out = await agree((p) => p.getBalance(addr).then((b) => b.toHexString()));
    return ethers.BigNumber.from(out == null ? 0 : out);
  }

  async function isRivet(contract, addr, { fresh = false } = {}) {
    return cached(`rivet|${lc(contract)}|${lc(addr)}`, async () => {
      if (await read(contract, "isAuthorized", [addr])) return true;
      for (const entry of (await read(contract, "getRivets", [])) || []) {
        if (lc(entry) === lc(contract)) continue;
        if (await read(entry, "isAuthorized", [addr])) return true;
      }
      return false;
    }, fresh);
  }

  async function roleOf(contract, section, addr, { fresh = false } = {}) {
    return cached(`role|${lc(contract)}|${section}|${lc(addr)}`, async () => Number((await read(contract, "roleOf", [section, addr])) || 0), fresh);
  }

  // The section role of a request signed by `signer` claiming `identity` — the
  // multisig two-hop, the one definition. r1 = roleOf(section, signer), the signer
  // as a principal, never dropped; r2 = roleOf(section, identity) only when the
  // identity vouches for the signer on chain (isAuthorized); the role is the larger.
  async function sectionRole(contract, section, signer, identity = null, { fresh = false } = {}) {
    let role = await roleOf(contract, section, signer, { fresh });
    if (identity && lc(identity) !== lc(signer)) {
      const vouches = await cached(`vouch|${lc(identity)}|${lc(signer)}`, async () => !!(await read(identity, "isAuthorized", [signer])), fresh);
      if (vouches) role = Math.max(role, await roleOf(contract, section, identity, { fresh }));
    }
    return role;
  }

  // May `signer` commit to this session's group? What the relay requires of a
  // commit, read by the caller itself: an owner rivet, or write on the section.
  async function mayCommit(contract, section, signer, identity = null, opts = {}) {
    if (await isRivet(contract, signer, opts)) return true;
    return (await sectionRole(contract, section, signer, identity, opts)) >= ROLE.WRITE;
  }

  // May `signer` ROTATE this session's key — remove, update, restore, or an add
  // that grows the tree? An owner device, or a section admin (Epoch: commit
  // authority). The same rule the relay's DS gate applies, read by the member.
  async function mayRotate(contract, section, signer, identity = null, opts = {}) {
    if (await isRivet(contract, signer, opts)) return true;
    return (await sectionRole(contract, section, signer, identity, opts)) >= ROLE.ADMIN;
  }

  return { isRivet, roleOf, sectionRole, mayCommit, mayRotate, view, hasCode, balanceOf, endpoints, quorum, maxHeadAgeMs };
}
