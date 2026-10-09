/**
 * Global test teardown
 * Runs once after all tests complete
 */
export default async function globalTeardown() {
  console.log('\n=== Epistery Test Suite Teardown ===\n');

  // Note: We don't clean up the test config directory
  // as it may be useful for debugging failed tests.
  // Blockchain state is permanent anyway.

  console.log('Test run complete.');
  console.log('\n=== Teardown Complete ===\n');
}
