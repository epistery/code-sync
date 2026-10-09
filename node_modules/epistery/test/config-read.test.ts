import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LocalConfig } from '../dist/utils/Config.js';

// PredictableFailure for config: ABSENT is empty, UNREADABLE throws. The old
// behaviour collapsed both into {} — and the caller's next step was to mint and
// save a wallet into the "empty" config.
describe('LocalConfig.read — absent is {}, failed is an error', () => {
  let home: string;
  let config: any;
  const savedHome = { HOME: process.env.HOME, EPISTERY_HOME: process.env.EPISTERY_HOME, USERPROFILE: process.env.USERPROFILE };

  beforeAll(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'epistery-config-read-'));
    process.env.HOME = home; process.env.EPISTERY_HOME = home; process.env.USERPROFILE = home;
    config = new LocalConfig();
    fs.mkdirSync(path.join(home, '.epistery', 'present.test'), { recursive: true });
    fs.writeFileSync(path.join(home, '.epistery', 'present.test', 'config.ini'), 'domain=present.test\n[wallet]\naddress=0x1\n');
    // a DIRECTORY where the file should be: readable path, unreadable config
    fs.mkdirSync(path.join(home, '.epistery', 'broken.test', 'config.ini'), { recursive: true });
  });
  afterAll(() => {
    Object.assign(process.env, savedHome);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('reads a present config', async () => {
    const d = await config.read('/present.test');
    expect(d.domain).toBe('present.test');
    expect(d.wallet.address).toBe('0x1');
  });

  it('answers {} for an absent config', async () => {
    expect(await config.read('/absent.test')).toEqual({});
  });

  it('throws, rather than answering {}, when the config cannot be read', async () => {
    await expect(config.read('/broken.test')).rejects.toThrow(/config read failed/);
    await config.setPath('/present.test');
    expect(config.data.domain).toBe('present.test');
    await expect(config.setPath('/broken.test')).rejects.toThrow(/config read failed/);
  });
});
