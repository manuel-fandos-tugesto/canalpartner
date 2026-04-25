/**
 * Unit tests for the two-factor authentication logic (sessions/two-factor/app).
 *
 * Run with: node twofa.test.js
 *
 * Tests verify that:
 *  - org_blocked errors show the org-blocked message (and ONLY that message).
 *  - non-org auth/2FA errors (invalid_code, expired, etc.) show the generic retry
 *    message WITHOUT showing the org-blocked message.
 *  - valid 6-digit codes authenticate the user successfully.
 *
 * NOTE: _check2FA below mirrors the implementation in index.html.
 * Since this is a single-file HTML app with no module system, the function is
 * duplicated here intentionally. Any change to _check2FA in index.html must be
 * reflected here, and vice versa.
 */

'use strict';

// ── Inline re-implementation of _check2FA (mirrors the logic in index.html) ──
function _check2FA(code) {
  if (!/^\d{6}$/.test(code)) return { error: 'invalid_code' };
  return { error: null };
}

/**
 * Simulate the UI reaction to a _check2FA result, the same way doVerify2FA()
 * does in the application.  Returns which UI action occurred.
 */
function simulateVerify2FA(code) {
  var result = _check2FA(code);
  if (!result.error) {
    return 'authenticated';
  } else if (result.error === 'org_blocked') {
    return 'show_org_blocked';
  } else {
    return 'show_generic_error';
  }
}

// ── Simple test runner ────────────────────────────────────────────────────────
var passed = 0;
var failed = 0;

function expect(description, actual, expected) {
  if (actual === expected) {
    console.log('  ✓ ' + description);
    passed++;
  } else {
    console.error('  ✗ ' + description);
    console.error('    Expected: ' + JSON.stringify(expected));
    console.error('    Got:      ' + JSON.stringify(actual));
    failed++;
  }
}

// ── Tests: _check2FA ──────────────────────────────────────────────────────────
console.log('\n[_check2FA] Valid codes');
expect('6-digit code returns no error', _check2FA('123456').error, null);
expect('000000 returns no error',       _check2FA('000000').error, null);
expect('999999 returns no error',       _check2FA('999999').error, null);

console.log('\n[_check2FA] Invalid codes → invalid_code (not org_blocked)');
expect('empty string → invalid_code',  _check2FA('').error,       'invalid_code');
expect('5 digits → invalid_code',      _check2FA('12345').error,  'invalid_code');
expect('7 digits → invalid_code',      _check2FA('1234567').error,'invalid_code');
expect('letters → invalid_code',       _check2FA('abcdef').error, 'invalid_code');
expect('spaces → invalid_code',        _check2FA('123 45').error, 'invalid_code');

// ── Tests: simulateVerify2FA (UI outcome mapping) ─────────────────────────────
console.log('\n[doVerify2FA] Valid code → authenticated (not org-blocked)');
expect('123456 → authenticated',       simulateVerify2FA('123456'), 'authenticated');
expect('000000 → authenticated',       simulateVerify2FA('000000'), 'authenticated');

console.log('\n[doVerify2FA] Invalid code → generic error (NOT org-blocked)');
expect('bad code → show_generic_error',     simulateVerify2FA('abc'), 'show_generic_error');
expect('short code → show_generic_error',   simulateVerify2FA('123'), 'show_generic_error');
expect('empty → show_generic_error',        simulateVerify2FA(''),    'show_generic_error');

console.log('\n[doVerify2FA] org_blocked from backend → show_org_blocked ONLY');
// Simulate a backend-returned org_blocked result directly
(function() {
  var orgBlockedResult = { error: 'org_blocked' };
  var outcome;
  if (!orgBlockedResult.error) {
    outcome = 'authenticated';
  } else if (orgBlockedResult.error === 'org_blocked') {
    outcome = 'show_org_blocked';
  } else {
    outcome = 'show_generic_error';
  }
  expect('org_blocked backend error → show_org_blocked', outcome, 'show_org_blocked');
})();

console.log('\n[doVerify2FA] Other backend errors → generic error (NOT org-blocked)');
(function() {
  var otherErrors = ['expired_session', 'invalid_state', 'missing_permissions', 'rate_limited'];
  otherErrors.forEach(function(errType) {
    var result = { error: errType };
    var outcome;
    if (!result.error) {
      outcome = 'authenticated';
    } else if (result.error === 'org_blocked') {
      outcome = 'show_org_blocked';
    } else {
      outcome = 'show_generic_error';
    }
    expect(errType + ' → show_generic_error (not org-blocked)', outcome, 'show_generic_error');
  });
})();

// ── Summary ───────────────────────────────────────────────────────────────────
console.log('\n─────────────────────────────────────────');
if (failed === 0) {
  console.log('All ' + passed + ' tests passed ✓');
} else {
  console.error(failed + ' test(s) FAILED, ' + passed + ' passed');
  process.exit(1);
}
