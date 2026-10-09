import { describe, it, expect, beforeAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * A host is one identity. The domain it pins with setDomain is the domain of
 * every request; it never takes its identity from a Host header unless it asks
 * for one identity per hostname explicitly ({ domains: 'request' }).
 */
describe('attach — the domain is pinned, not switched per request', () => {
  let Epistery: any;

  beforeAll(async () => {
    const testConfigPath = path.resolve(__dirname, '..', 'config');
    process.env.EPISTERY_HOME = testConfigPath;
    process.env.HOME = testConfigPath;
    ({ Epistery } = await import('../../index.mjs'));
  });

  it('answers 503 for a host that pinned no domain, rather than minting one from the Host header', async () => {
    const app = express();
    const epistery = await Epistery.connect({});
    await epistery.attach(app, '/');
    app.get('/probe', (req, res) => res.json({ domain: epistery.domainName || null }));

    const res = await request(app).get('/probe').set('Host', 'stray.example').expect(503);
    expect(res.body.error).toMatch(/pinned no domain/);
    expect(epistery.domainName).toBeFalsy();
  });

  it('answers every request as the pinned domain, whatever the Host header says', async () => {
    const app = express();
    const epistery = await Epistery.connect({});
    await epistery.setDomain('localhost');
    await epistery.attach(app, '/');
    app.get('/probe', (req, res) => res.json({ domain: epistery.domainName }));

    const res = await request(app).get('/probe').set('Host', 'other.example').expect(200);
    expect(res.body.domain).toBe('localhost');
  });

  it('switches per request only when asked: { domains: "request" }', async () => {
    const app = express();
    const epistery = await Epistery.connect({});
    await epistery.setDomain('localhost');
    await epistery.attach(app, '/', { domains: 'request' });
    app.get('/probe', (req, res) => res.json({ domain: epistery.domainName }));

    const res = await request(app).get('/probe').set('Host', 'localhost').expect(200);
    expect(res.body.domain).toBe('localhost');
  });
});
