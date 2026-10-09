import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    // Test environment
    environment: 'node',

    // Global setup and teardown
    globalSetup: './test/setup.ts',
    globalTeardown: './test/teardown.ts',

    // Test file patterns
    include: ['test/**/*.test.ts'],
    exclude: ['node_modules/**', 'dist/**'],

    // Timeouts - blockchain operations need longer timeouts
    testTimeout: 120000,      // 120 seconds for individual tests
    hookTimeout: 180000,      // 3 minutes for setup/teardown hooks

    // Sequential execution to avoid nonce conflicts on blockchain
    sequence: {
      shuffle: false,
    },
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,    // Single fork to prevent nonce conflicts
      }
    },

    // Coverage
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: [
        'routes/**/*.mjs',
        'src/**/*.ts'
      ],
      exclude: [
        'test/**',
        'node_modules/**',
        'dist/**',
        'artifacts/**',
        'demo/**'
      ],
      thresholds: {
        lines: 50,
        functions: 50,
        branches: 40,
        statements: 50
      }
    },

    // Reporter
    reporters: ['verbose'],

    // Alias for imports
    alias: {
      '@test': path.resolve(__dirname, './test'),
      '@routes': path.resolve(__dirname, './routes'),
      '@src': path.resolve(__dirname, './src')
    }
  }
});
