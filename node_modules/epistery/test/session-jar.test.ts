import { describe, it, expect } from 'vitest';
// @ts-ignore - plain .mjs module, no types
import * as jar from '../session-jar.mjs';

const session = (signer: string, extra: any = {}) => ({
  signerAddress: signer,
  contractAddress: null,
  publicKey: '0x' + '11'.repeat(64),
  authenticated: false,
  timestamp: new Date().toISOString(),
  ...extra,
});

const req = (cookie: string | null, opts: { tab?: string; url?: string } = {}) => ({
  headers: {
    ...(cookie ? { cookie: `_epistery=${cookie}` } : {}),
    ...(opts.tab ? { 'x-epistery-tab': opts.tab } : {}),
  },
  url: opts.url || '/api/me',
});

describe('session jar', () => {
  it('keeps two tabs on two different sessions', () => {
    let cookie = jar.put(null, 'tabA', session('0xAAA'));
    cookie = jar.put(cookie, 'tabB', session('0xBBB'));

    const a = jar.select(jar.decode(cookie), 'tabA');
    const b = jar.select(jar.decode(cookie), 'tabB');
    expect(a.signerAddress).toBe('0xAAA');
    expect(b.signerAddress).toBe('0xBBB');
  });

  it('a request naming an unknown tab gets NO session, not the default', () => {
    const cookie = jar.put(null, 'tabA', session('0xAAA'));
    expect(jar.select(jar.decode(cookie), 'tabZ')).toBeNull();
  });

  it('a request naming no tab gets the most recent session', () => {
    let cookie = jar.put(null, 'tabA', session('0xAAA'));
    cookie = jar.put(cookie, 'tabB', session('0xBBB'));
    expect(jar.select(jar.decode(cookie), null).signerAddress).toBe('0xBBB');
  });

  it('reads a pre-v2 flat cookie as the anonymous slot', () => {
    const legacy = Buffer.from(JSON.stringify(session('0xOLD'))).toString('base64');
    const decoded = jar.decode(legacy);
    expect(jar.select(decoded, null).signerAddress).toBe('0xOLD');
    expect(jar.select(decoded, jar.ANON_SLOT).signerAddress).toBe('0xOLD');
    // A legacy cookie plus a new tab: the old session survives alongside it.
    const cookie = jar.put(legacy, 'tabA', session('0xAAA'));
    expect(jar.select(jar.decode(cookie), jar.ANON_SLOT).signerAddress).toBe('0xOLD');
    expect(jar.select(jar.decode(cookie), 'tabA').signerAddress).toBe('0xAAA');
  });

  it('a headerless client writes and reads the anonymous slot', () => {
    const cookie = jar.put(null, null, session('0xCLI'));
    expect(jar.select(jar.decode(cookie), null).signerAddress).toBe('0xCLI');
    expect(jar.select(jar.decode(cookie), jar.ANON_SLOT).signerAddress).toBe('0xCLI');
  });

  it('evicts the oldest slot instead of growing the cookie past its limit', () => {
    let cookie: string | null = null;
    for (let i = 0; i < 12; i++) {
      cookie = jar.put(cookie, `tab${i}`, {
        ...session(`0x${i}`),
        timestamp: new Date(1700000000000 + i * 1000).toISOString(),
      });
    }
    const decoded = jar.decode(cookie!);
    const slots = Object.keys(decoded.s);
    expect(slots.length).toBeLessThanOrEqual(6);
    expect(cookie!.length).toBeLessThan(4000);
    // The newest survives; the oldest is gone.
    expect(slots).toContain('tab11');
    expect(slots).not.toContain('tab0');
  });

  it('never evicts the slot being written', () => {
    let cookie: string | null = null;
    for (let i = 0; i < 8; i++) cookie = jar.put(cookie, `tab${i}`, session(`0x${i}`));
    expect(jar.select(jar.decode(cookie!), 'tab7').signerAddress).toBe('0x7');
  });

  it('reads the tab from the header, and from ?_tab= when there is none', () => {
    expect(jar.tabFromRequest(req(null, { tab: 'tabA' }))).toBe('tabA');
    expect(jar.tabFromRequest(req(null, { url: '/ws?_tab=tabB' }))).toBe('tabB');
    expect(jar.tabFromRequest(req(null))).toBeNull();
    // A header beats the query string — a WebSocket is the only thing that has
    // to use the query, and it has no header to conflict with.
    expect(jar.tabFromRequest(req(null, { tab: 'tabA', url: '/ws?_tab=tabB' }))).toBe('tabA');
  });

  it('finds the cookie in the raw header when no parser has run', () => {
    const cookie = jar.put(null, 'tabA', session('0xAAA'));
    const r: any = req(cookie, { tab: 'tabA' });
    expect(jar.cookieFromRequest(r)).toBe(cookie);
    // And prefers the express-parsed jar when there is one.
    r.cookies = { _epistery: 'parsed-wins' };
    expect(jar.cookieFromRequest(r)).toBe('parsed-wins');
  });

  it('treats a corrupt or absent cookie as no session', () => {
    expect(jar.decode(null)).toBeNull();
    expect(jar.decode('not-base64-json')).toBeNull();
    expect(jar.select(null, 'tabA')).toBeNull();
  });
});
