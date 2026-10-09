import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
// @ts-ignore - plain .mjs module, no types
import {
  issueOriginCertificate,
  verifyOriginCertificate,
  originCertificateMessage,
  ORIGIN_CERT_MAX_AGE_MS,
} from '../client/origin-certificate.mjs';

// The origin certificate is the rung that binds a DEVICE to a DOMAIN. A rivet's
// own signature binds an event to the device, and a signed manifest binds the
// domain to its chain identity; without this middle rung a domain name inside a
// message signed by page JS is self-asserted and no third party can check it.
//
// Every negative case below is a way that rung could be quietly bypassed, which
// is why they are tested individually rather than as one "bad input" case.

const domain = 'epistery.com';

const actors = () => ({
  domainWallet: ethers.Wallet.createRandom(),
  otherWallet: ethers.Wallet.createRandom(),
  rivet: ethers.Wallet.createRandom().address,
  otherRivet: ethers.Wallet.createRandom().address,
});

describe('origin certificate — message', () => {
  it('normalizes address casing, host casing and port into the signed bytes', () => {
    const a = originCertificateMessage({ rivet: '0xAbC0000000000000000000000000000000000001', domain: 'Epistery.COM:443', ts: 1700000000000 });
    const b = originCertificateMessage({ rivet: '0xabc0000000000000000000000000000000000001', domain: 'epistery.com', ts: 1700000000000 });
    expect(a).toBe(b);
    expect(a.split('\n')).toHaveLength(5);
    expect(a.split('\n')[0]).toBe('epistery-origin-certificate');
  });

  it('refuses a malformed rivet, an empty domain and a non-positive ts', () => {
    expect(() => originCertificateMessage({ rivet: 'nope', domain, ts: 1 })).toThrow(/rivet/);
    expect(() => originCertificateMessage({ rivet: ethers.Wallet.createRandom().address, domain: '', ts: 1 })).toThrow(/domain/);
    expect(() => originCertificateMessage({ rivet: ethers.Wallet.createRandom().address, domain, ts: 0 })).toThrow(/ts/);
  });
});

describe('origin certificate — issue and verify', () => {
  it('verifies against the wallet the domain publishes, and recovers that signer', async () => {
    const { domainWallet, rivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain }, domainWallet);
    expect(cert.rivet).toBe(rivet.toLowerCase());
    const r = verifyOriginCertificate(cert, { domain, rivet, expectDomainWallet: domainWallet.address }, ethers);
    expect(r.ok).toBe(true);
    expect(r.signer?.toLowerCase()).toBe(domainWallet.address.toLowerCase());
  });

  it('accepts the same certificate presented with checksummed casing and a port', async () => {
    const { domainWallet, rivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain }, domainWallet);
    const r = verifyOriginCertificate(cert, { domain: 'EPISTERY.com:443', rivet, expectDomainWallet: domainWallet.address }, ethers);
    expect(r.ok).toBe(true);
  });

  it('rejects a signature from any wallet but the domain\'s', async () => {
    const { domainWallet, otherWallet, rivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain }, otherWallet);
    const r = verifyOriginCertificate(cert, { domain, rivet, expectDomainWallet: domainWallet.address }, ethers);
    expect(r.ok).toBe(false);
  });

  // A certificate that verifies without being tied to the device and host being
  // asked about would be a universal certificate — valid everywhere, for anyone.
  it('rejects a valid certificate that names a different rivet', async () => {
    const { domainWallet, rivet, otherRivet } = actors();
    const cert = await issueOriginCertificate({ rivet: otherRivet, domain }, domainWallet);
    const r = verifyOriginCertificate(cert, { domain, rivet, expectDomainWallet: domainWallet.address }, ethers);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/different rivet/);
  });

  it('rejects a valid certificate that names a different domain', async () => {
    const { domainWallet, rivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain: 'somewhere.else' }, domainWallet);
    const r = verifyOriginCertificate(cert, { domain, rivet, expectDomainWallet: domainWallet.address }, ethers);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/different domain/);
  });

  it('rejects an edited field, because the signature no longer recovers', async () => {
    const { domainWallet, rivet, otherRivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain }, domainWallet);
    for (const tampered of [{ ...cert, domain: 'evil.example' }, { ...cert, rivet: otherRivet }, { ...cert, ts: cert.ts + 1 }]) {
      const r = verifyOriginCertificate(tampered, { expectDomainWallet: domainWallet.address }, ethers);
      expect(r.ok).toBe(false);
    }
  });

  it('expires, and refuses a timestamp from the future', async () => {
    const { domainWallet, rivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain }, domainWallet);
    const at = (now: number) => verifyOriginCertificate(cert, { domain, rivet, expectDomainWallet: domainWallet.address, now }, ethers);
    expect(at(cert.ts + ORIGIN_CERT_MAX_AGE_MS - 1000).ok).toBe(true);
    expect(at(cert.ts + ORIGIN_CERT_MAX_AGE_MS + 1000).ok).toBe(false);
    expect(at(cert.ts + ORIGIN_CERT_MAX_AGE_MS + 1000).reason).toMatch(/stale/);
    expect(at(cert.ts - 120_000).reason).toMatch(/future/);
  });

  // "No certificate" and "a certificate that does not hold" must be
  // distinguishable: an older host simply issues none, and that is not a failure
  // to report as tampering.
  it('reports an absent certificate as absent', () => {
    const r = verifyOriginCertificate(null, { domain, expectDomainWallet: ethers.Wallet.createRandom().address }, ethers);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('absent');
  });

  it('refuses an unknown envelope version rather than guessing', async () => {
    const { domainWallet, rivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain }, domainWallet);
    const r = verifyOriginCertificate({ ...cert, v: '2' }, { domain, rivet, expectDomainWallet: domainWallet.address }, ethers);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/version/);
  });

  // Checking a certificate against an address the presenter supplied proves
  // nothing, so with no published wallet to check against the answer is no.
  it('refuses to verify when no published domain wallet is given', async () => {
    const { domainWallet, rivet } = actors();
    const cert = await issueOriginCertificate({ rivet, domain }, domainWallet);
    const r = verifyOriginCertificate(cert, { domain, rivet }, ethers);
    expect(r.ok).toBe(false);
  });
});
