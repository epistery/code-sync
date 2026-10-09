import { describe, it, expect } from 'vitest';
import { keyExchangeMessage, serverResponseMessage } from '../client/key-exchange-message.mjs';

describe('keyExchangeMessage — the one string a device signs to prove its key', () => {
  it('is the exact bytes every host and authority verifies', () => {
    expect(keyExchangeMessage({ address: '0xabc', challenge: '0x01' })).toBe('Epistery Key Exchange - 0xabc - 0x01');
  });
});

describe('serverResponseMessage — the one string a host signs back', () => {
  it('is the exact bytes the witness and the CLI verify against the host address', () => {
    expect(serverResponseMessage({ address: '0xhost', challenge: '0x02' })).toBe('Epistery Server Response - 0xhost - 0x02');
  });
});
