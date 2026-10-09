import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ethers } from 'ethers';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
// @ts-ignore - plain .mjs module, no types
import { chainReader, isChainReadFailure } from '../client/chain-read.mjs';

// Attestation reads (EpisteryChainReads, Proposal A): answered by an owned node or
// not at all. A fake node decodes real calldata, so the reader's encoding and the
// ethers error shapes it classifies are the real ones.

const CONTRACT = ethers.Wallet.createRandom().address;
const SESSION = 'recipes';
const RIVET = ethers.Wallet.createRandom().address;
const WRITER = ethers.Wallet.createRandom().address;
const ADMIN = ethers.Wallet.createRandom().address;
const STRANGER = ethers.Wallet.createRandom().address;
// A second contract that admits STRANGER as its rivet, so a request signed by
// STRANGER claiming IDENTITY is credited IDENTITY's section role (the two-hop).
const IDENTITY = ethers.Wallet.createRandom().address;
const iface = new ethers.utils.Interface([
  'function isAuthorized(address) view returns (bool)',
  'function getRivets() view returns (address[])',
  'function roleOf(string section, address account) view returns (uint8)',
  'function getSectionNames() view returns (string[])',
]);
let sectionNames = ['recipes', '_profile'];

// mode: 'ok' answers; 'lie' says everyone is a rivet; 'hang' never answers; 'down' HTTP 503; 'forbidden' HTTP 403 (the Infura settings shape);
// 'stale' answers everything correctly from a head sealed hours ago (a node whose chain has stopped);
// 'revert-as-result' is a node that reports a contract's revert as the call's RESULT bytes (Panic 0x32), not as an error
function fakeNode(mode: () => string) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const m = mode();
      if (m === 'hang') return;   // a jammed node: takes the request, never answers
      if (!['ok', 'lie', 'stale', 'revert-as-result'].includes(m)) { res.writeHead(m === 'down' ? 503 : 403); return res.end('{"error":"no"}'); }
      const rq = JSON.parse(body);
      const reply = (result: any) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: rq.id, result })); };
      if (rq.method === 'eth_chainId') return reply('0x89');
      if (rq.method === 'eth_getBlockByNumber') {
        const ts = Math.floor(Date.now() / 1000) - (m === 'stale' ? 3 * 3600 : 1);
        return reply({ number: '0x5a63500', hash: '0x' + 'ab'.repeat(32), timestamp: '0x' + ts.toString(16) });
      }
      const a = (x: string) => x.toLowerCase();
      if (rq.method === 'eth_getBalance') return reply(a(rq.params[0]) === a(RIVET) ? '0x8ac7230489e80000' : '0x0');   // 10 POL, else nothing
      if (rq.method === 'eth_getCode') return reply([a(CONTRACT), a(IDENTITY)].includes(a(rq.params[0])) ? '0x6001' : '0x');
      const { to, data } = rq.params[0];
      if (a(to) === a(IDENTITY)) {
        const tx = iface.parseTransaction({ data });
        if (tx.name === 'isAuthorized') return reply(iface.encodeFunctionResult('isAuthorized', [a(tx.args[0]) === a(STRANGER)]));
        return reply('0x');
      }
      if (to.toLowerCase() !== CONTRACT.toLowerCase()) return reply('0x');   // an EOA: no code, no data
      const tx = iface.parseTransaction({ data });
      if (tx.name === 'isAuthorized') return reply(iface.encodeFunctionResult('isAuthorized', [m === 'lie' || a(tx.args[0]) === a(RIVET)]));
      if (tx.name === 'getRivets') return reply(m === 'revert-as-result' ? '0x4e487b710000000000000000000000000000000000000000000000000000000000000032' : iface.encodeFunctionResult('getRivets', [[RIVET]]));
      if (tx.name === 'getSectionNames') return reply(iface.encodeFunctionResult('getSectionNames', [sectionNames]));
      const who = a(tx.args[1]);
      const role = tx.args[0] !== SESSION ? 0 : who === a(WRITER) ? 2 : who === a(ADMIN) ? 3 : who === a(IDENTITY) ? 3 : 0;
      return reply(iface.encodeFunctionResult('roleOf', [role]));
    });
  });
  return server;
}

const modes = ['ok', 'ok', 'ok'];
const servers: http.Server[] = [];
const urls: string[] = [];
const listen = (sv: http.Server) => new Promise<string>((r) => sv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(sv.address() as any).port}/`)));

beforeAll(async () => {
  for (let i = 0; i < 3; i++) { const sv = fakeNode(() => modes[i]); servers.push(sv); urls.push(await listen(sv)); }
});
afterAll(() => servers.forEach((sv) => { (sv as any).closeAllConnections?.(); sv.close(); }));

const set = (...m: string[]) => m.forEach((x, i) => (modes[i] = x));
const reader = (n: number, quorum: number | null = null, timeoutMs = 3000) => chainReader({ rpcs: urls.slice(0, n), quorum, chainId: 137, ethers, ttlMs: 0, timeoutMs });

describe('chainReader — k-of-n, like a multisig', () => {
  it('one node, quorum 1 (today): answers rivet, writer, stranger', async () => {
    set('ok');
    const r = reader(1);
    expect(r.quorum).toBe(1);
    expect(await r.isRivet(CONTRACT, RIVET)).toBe(true);
    expect(await r.mayCommit(CONTRACT, SESSION, WRITER)).toBe(true);
    expect(await r.mayCommit(CONTRACT, SESSION, STRANGER)).toBe(false);
  });

  it('an EOA among the contract rivets is an answer ("no"), not a read failure', async () => {
    set('ok');
    expect(await reader(1).isRivet(CONTRACT, STRANGER)).toBe(false);
  });

  it('three nodes default to 2 of 3', () => {
    expect(reader(3).quorum).toBe(2);
  });

  it('2 of 3: a node that is down costs nothing', async () => {
    set('down', 'ok', 'ok');
    expect(await reader(3).mayCommit(CONTRACT, SESSION, RIVET)).toBe(true);
  });

  it('2 of 3: one lying node neither blocks nor decides', async () => {
    set('lie', 'ok', 'ok');
    expect(await reader(3).mayCommit(CONTRACT, SESSION, STRANGER)).toBe(false);
    set('ok', 'lie', 'ok');
    expect(await reader(3).mayCommit(CONTRACT, SESSION, RIVET)).toBe(true);
  });

  it('2 of 3: a jammed (hanging) node does not hold the read — it settles on the two', async () => {
    set('hang', 'ok', 'ok');
    const t = Date.now();
    expect(await reader(3, null, 10000).mayCommit(CONTRACT, SESSION, RIVET)).toBe(true);
    expect(Date.now() - t).toBeLessThan(5000);
  });

  it('2 of 3: two colluding nodes decide — the stated limit', async () => {
    set('lie', 'lie', 'ok');
    expect(await reader(3).mayCommit(CONTRACT, SESSION, STRANGER)).toBe(true);
  });

  it('a strict host (3 of 3): one node down is CHAIN_UNREACHABLE, one lying is CHAIN_DISAGREES', async () => {
    set('down', 'ok', 'ok');
    await expect(reader(3, 3).mayCommit(CONTRACT, SESSION, RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
    set('lie', 'ok', 'ok');
    await expect(reader(3, 3).mayCommit(CONTRACT, SESSION, STRANGER)).rejects.toMatchObject({ code: 'CHAIN_DISAGREES' });
  });

  it('a loose host (1 of 2): two answers both reaching the quorum is a refusal, not a choice', async () => {
    set('lie', 'ok');
    await expect(reader(2, 1).mayCommit(CONTRACT, SESSION, STRANGER)).rejects.toMatchObject({ code: 'CHAIN_DISAGREES' });
  });

  it('a node whose head is stale is not an answer: at 1 of 1 the read is refused and says so', async () => {
    set('stale');
    await expect(reader(1).isRivet(CONTRACT, RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE', message: expect.stringMatching(/is stale: head #\d+ is \d+s old, 120s allowed/) });
  });

  it('2 of 3: one stale node costs nothing — the two fresh ones answer', async () => {
    set('stale', 'ok', 'ok');
    expect(await reader(3).isRivet(CONTRACT, RIVET)).toBe(true);
    set('ok', 'stale', 'stale');
    await expect(reader(3).isRivet(CONTRACT, RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
  });

  it('a node that catches up answers again, once its head verdict is re-asked', async () => {
    set('stale');
    const r = chainReader({ rpcs: urls.slice(0, 1), chainId: 137, ethers, ttlMs: 0, timeoutMs: 3000, headTtlMs: 0 });
    await expect(r.isRivet(CONTRACT, RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
    set('ok');
    expect(await r.isRivet(CONTRACT, RIVET)).toBe(true);
  });

  it('a revert returned as the call RESULT is an answer of nothing, like a revert returned as an error', async () => {
    set('revert-as-result');
    // getRivets panics (array out of bounds) on this contract: isRivet still answers — by isAuthorized — and never throws
    expect(await reader(1).isRivet(CONTRACT, RIVET)).toBe(true);
    expect(await reader(1).isRivet(CONTRACT, STRANGER)).toBe(false);
    expect(await reader(1).view(CONTRACT, 'function getRivets() view returns (address[])', 'getRivets')).toBeNull();
  });

  it('balanceOf: the attested balance, k-of-n like any other read, refused when the node is stale', async () => {
    set('ok');
    expect((await reader(1).balanceOf(RIVET)).toString()).toBe('10000000000000000000');
    expect((await reader(1).balanceOf(STRANGER)).toString()).toBe('0');
    set('stale');
    await expect(reader(1).balanceOf(RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
    set('ok', 'stale', 'ok');
    expect((await reader(3).balanceOf(RIVET)).toString()).toBe('10000000000000000000');
  });

  it('observe hears every read settle — a refusal with its code, an answer as ok — and cannot break the read', async () => {
    const seen: any[] = [];
    const r = chainReader({ rpcs: urls.slice(0, 1), chainId: 137, ethers, ttlMs: 0, timeoutMs: 3000, headTtlMs: 0, observe: (e: any) => { seen.push(e); throw new Error('observer bug'); } });
    set('stale');
    await expect(r.isRivet(CONTRACT, RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
    set('ok');
    expect(await r.isRivet(CONTRACT, RIVET)).toBe(true);
    expect(seen[0]).toMatchObject({ ok: false, code: 'CHAIN_UNREACHABLE' });
    expect(seen[0].message).toMatch(/is stale/);
    expect(seen.some((e) => e.ok === true)).toBe(true);
  });

  it('refuses to exist with a non-positive head age', () => {
    expect(() => chainReader({ rpcs: urls.slice(0, 1), chainId: 137, ethers, maxHeadAgeMs: 0 })).toThrow(/maxHeadAgeMs/);
  });

  it('no node answering in time is CHAIN_UNREACHABLE — never a "no", never a guess', async () => {
    set('hang');
    await expect(reader(1, null, 300).mayCommit(CONTRACT, SESSION, RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
    set('down', 'forbidden', 'down');
    await expect(reader(3).mayCommit(CONTRACT, SESSION, RIVET)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
  });

  it('refuses to exist without a node, or with a quorum outside 1..n', () => {
    expect(() => chainReader({ rpcs: [], chainId: 137, ethers })).toThrow(/owned node/);
    expect(() => chainReader({ rpcs: urls, quorum: 4, chainId: 137, ethers })).toThrow(/quorum/);
    expect(() => chainReader({ rpcs: urls, quorum: 0, chainId: 137, ethers })).toThrow(/quorum/);
  });
});

describe('chainReader — the verbs the relay and the member share', () => {
  it('hasCode: a contract holds code, an EOA does not — a read, not an inferred revert', async () => {
    set('ok');
    expect(await reader(1).hasCode(CONTRACT)).toBe(true);
    expect(await reader(1).hasCode(STRANGER)).toBe(false);
  });

  it('hasCode with no node answering is CHAIN_UNREACHABLE, never "no code"', async () => {
    set('down');
    await expect(reader(1, null, 300).hasCode(CONTRACT)).rejects.toMatchObject({ code: 'CHAIN_UNREACHABLE' });
  });

  it('view: any named function, decoded; null where the chain answers nothing', async () => {
    set('ok');
    const r = reader(1);
    expect(await r.view(CONTRACT, 'function getSectionNames() view returns (string[])', 'getSectionNames')).toEqual(['recipes', '_profile']);
    expect(await r.view(STRANGER, ['function getSectionNames() view returns (string[])'], 'getSectionNames')).toBe(null);
    expect(Number(await r.view(CONTRACT, 'function roleOf(string,address) view returns (uint8)', 'roleOf', [SESSION, ADMIN]))).toBe(3);
    // JSON ABI fragments work too, and two different ones do not share an Interface
    const jsonAbi = [{ type: 'function', name: 'getSectionNames', stateMutability: 'view', inputs: [], outputs: [{ type: 'string[]' }] }];
    const jsonAbi2 = [{ type: 'function', name: 'getRivets', stateMutability: 'view', inputs: [], outputs: [{ type: 'address[]' }] }];
    expect(await r.view(CONTRACT, jsonAbi, 'getSectionNames')).toEqual(['recipes', '_profile']);
    expect((await r.view(CONTRACT, jsonAbi2, 'getRivets')).map((a: string) => a.toLowerCase())).toEqual([RIVET.toLowerCase()]);
  });

  it('sectionRole: the signer as principal, and the identity that vouches for it — the larger role', async () => {
    set('ok');
    const r = reader(1);
    expect(await r.sectionRole(CONTRACT, SESSION, WRITER)).toBe(2);
    expect(await r.sectionRole(CONTRACT, SESSION, STRANGER)).toBe(0);
    expect(await r.sectionRole(CONTRACT, SESSION, STRANGER, IDENTITY)).toBe(3);   // IDENTITY vouches for STRANGER and holds admin
    expect(await r.sectionRole(CONTRACT, SESSION, RIVET, IDENTITY)).toBe(0);      // IDENTITY does not vouch for RIVET: no credit
  });

  it('mayRotate: an owner rivet or a section admin, never a writer', async () => {
    set('ok');
    const r = reader(1);
    expect(await r.mayRotate(CONTRACT, SESSION, RIVET)).toBe(true);
    expect(await r.mayRotate(CONTRACT, SESSION, ADMIN)).toBe(true);
    expect(await r.mayRotate(CONTRACT, SESSION, WRITER)).toBe(false);
    expect(await r.mayCommit(CONTRACT, SESSION, WRITER)).toBe(true);
    expect(await r.mayRotate(CONTRACT, SESSION, STRANGER, IDENTITY)).toBe(true);   // through the vouching identity's admin
  });

  it('fresh: a caller that just acted reads past the cache', async () => {
    set('ok');
    const r = chainReader({ rpcs: urls.slice(0, 1), chainId: 137, ethers, ttlMs: 60_000, timeoutMs: 3000 });
    expect(await r.view(CONTRACT, 'function getSectionNames() view returns (string[])', 'getSectionNames')).toEqual(['recipes', '_profile']);
    sectionNames = ['recipes', '_profile', 'new'];
    expect(await r.view(CONTRACT, 'function getSectionNames() view returns (string[])', 'getSectionNames')).toEqual(['recipes', '_profile']);          // cached
    expect(await r.view(CONTRACT, 'function getSectionNames() view returns (string[])', 'getSectionNames', [], { fresh: true })).toEqual(['recipes', '_profile', 'new']);
    sectionNames = ['recipes', '_profile'];
  });
});

describe('isChainReadFailure — the one classifier', () => {
  it('transport errors are failures', () => {
    for (const code of ['SERVER_ERROR', 'TIMEOUT', 'NETWORK_ERROR']) expect(isChainReadFailure({ code })).toBe(true);
  });
  it('a CALL_EXCEPTION with no revert bytes is a failure (the fabricated shape)', () => {
    expect(isChainReadFailure({ code: 'CALL_EXCEPTION', data: '0x' })).toBe(true);
    expect(isChainReadFailure({ code: 'CALL_EXCEPTION', data: '0x08c379a0', error: { status: 403 } })).toBe(true);
  });
  it('a revert with its bytes is an answer', () => {
    expect(isChainReadFailure({ code: 'CALL_EXCEPTION', data: '0x08c379a0' })).toBe(false);
  });
});

describe('attestationConfig — owned nodes and quorum from config', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-attest-'));
  const saved = { HOME: process.env.HOME, URL: process.env.EPISTERY_CONFIG_URL };
  const write = (ini: string) => { fs.mkdirSync(path.join(home, '.epistery'), { recursive: true }); fs.writeFileSync(path.join(home, '.epistery', 'config.ini'), ini); };
  beforeAll(() => { process.env.HOME = home; delete process.env.EPISTERY_CONFIG_URL; });
  afterAll(() => { process.env.HOME = saved.HOME; if (saved.URL) process.env.EPISTERY_CONFIG_URL = saved.URL; });

  it('reads attest[] and quorum from the chain section, by alias', async () => {
    write('[chains.polygon]\nattest[] = https://node1.example/\nattest[] = https://node2.example/\nattest[] = https://node3.example/\nquorum = 2\n');
    const { attestationConfig } = await import('../dist/chains/index.js');
    expect(await attestationConfig(137)).toEqual({ rpcs: ['https://node1.example/', 'https://node2.example/', 'https://node3.example/'], quorum: 2 });
  });

  it('quorum unset is null — the reader takes a majority', async () => {
    write('[chains.polygon]\nattest[] = https://node1.example/\n');
    const { attestationConfig } = await import('../dist/chains/index.js');
    expect((await attestationConfig(137)).quorum).toBe(null);
  });

  it('a quorum above the node count throws', async () => {
    write('[chains.polygon]\nattest[] = https://node1.example/\nquorum = 2\n');
    const { attestationConfig } = await import('../dist/chains/index.js');
    await expect(attestationConfig(137)).rejects.toThrow(/quorum/);
  });

  it('no node configured throws — no fallthrough to a public endpoint', async () => {
    write('[provider]\npublicRpc = https://public.example/\n');
    const { attestationConfig } = await import('../dist/chains/index.js');
    await expect(attestationConfig(137)).rejects.toThrow(/No attestation node/);
  });
});
