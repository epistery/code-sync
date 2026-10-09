import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { ROLE, ROLE_NAME, roleName } from '../client/chain-read.mjs';

// The role table is the contract's. Read the constants out of the Solidity
// source so the JS declaration cannot drift from what the chain stores.
describe('ROLE — the EpisteryAccess role table', () => {
  const sol = fs.readFileSync(path.resolve(__dirname, '..', 'contracts', 'EpisteryAccess.sol'), 'utf8');
  const fromSol: Record<string, number> = {};
  for (const m of sol.matchAll(/uint8 constant ROLE_([A-Z]+)\s*=\s*(\d+);/g)) fromSol[m[1]] = Number(m[2]);

  it('matches contracts/EpisteryAccess.sol exactly', () => {
    expect(Object.keys(fromSol).sort()).toEqual(['ADMIN', 'NONE', 'OWNER', 'READ', 'WRITE']);
    expect({ ...ROLE }).toEqual(fromSol);
  });

  it('is frozen and names every value', () => {
    expect(Object.isFrozen(ROLE)).toBe(true);
    for (const [name, value] of Object.entries(ROLE)) expect(ROLE_NAME[value as keyof typeof ROLE_NAME]).toBe(name.toLowerCase());
    expect(roleName('3')).toBe('admin');
    expect(roleName(9)).toBeNull();
  });
});
