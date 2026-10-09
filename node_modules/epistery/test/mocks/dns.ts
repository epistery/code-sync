import { vi } from 'vitest';

/**
 * DNS Mock for testing domain verification
 *
 * The auth.mjs route uses dns.resolveTxt to verify domain ownership
 * via TXT records. This mock allows testing without actual DNS lookups.
 */

// Store mock TXT records
const mockTxtRecords: Map<string, string[][]> = new Map();

/**
 * Set mock TXT records for a domain
 * @param domain The domain to mock
 * @param records Array of TXT record arrays (DNS returns array of arrays)
 */
export function setMockTxtRecords(domain: string, records: string[][]): void {
  mockTxtRecords.set(domain, records);
}

/**
 * Clear mock TXT record for a domain
 */
export function clearMockTxtRecords(domain: string): void {
  mockTxtRecords.delete(domain);
}

/**
 * Clear all mock TXT records
 */
export function clearAllMockTxtRecords(): void {
  mockTxtRecords.clear();
}

/**
 * Mock implementation of dns.resolveTxt
 * Returns stored mock records or throws ENODATA error
 */
export async function mockResolveTxt(domain: string): Promise<string[][]> {
  const records = mockTxtRecords.get(domain);

  if (!records) {
    const error = new Error(`queryTxt ENODATA ${domain}`);
    (error as any).code = 'ENODATA';
    throw error;
  }

  return records;
}

/**
 * Setup DNS mocks for the test environment
 * Call this in beforeAll to replace dns.resolveTxt
 */
export function setupDnsMocks(): void {
  // Mock the dns module
  vi.mock('dns', async () => {
    const actual = await vi.importActual('dns');
    return {
      ...actual,
      promises: {
        ...(actual as any).promises,
        resolveTxt: mockResolveTxt
      }
    };
  });
}

/**
 * Restore original DNS functions
 * Call this in afterAll
 */
export function restoreDnsMocks(): void {
  vi.restoreAllMocks();
}

/**
 * Helper to create a challenge TXT record
 */
export function createChallengeTxtRecord(challengeToken: string): string[][] {
  return [[challengeToken]];
}

/**
 * Example usage:
 *
 * import { setMockTxtRecords, clearAllMockTxtRecords, setupDnsMocks } from '../mocks/dns';
 *
 * beforeAll(() => {
 *   setupDnsMocks();
 * });
 *
 * afterAll(() => {
 *   clearAllMockTxtRecords();
 * });
 *
 * it('should verify domain via DNS', async () => {
 *   const challengeToken = 'abc123...';
 *   setMockTxtRecords('example.com', [[challengeToken]]);
 *
 *   // Now auth.mjs will find the TXT record
 *   const response = await request.get('/auth/dns/claim')
 *     .query({ address: '0x...' })
 *     .set('Host', 'example.com');
 *
 *   expect(response.status).toBe(200);
 * });
 */
