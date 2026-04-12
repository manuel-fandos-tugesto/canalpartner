/* sessions/two-factor/app/twofa.test.js
 * Unit tests for the TwoFA error-classification module.
 * Run with: node --test sessions/two-factor/app/twofa.test.js
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const TwoFA  = require('./twofa.js');

// ── Helpers ──────────────────────────────────────────────────────────────────

const { ERROR_TYPES, classifyError } = TwoFA;

// ── ORG_POLICY_BLOCKED — must require an explicit indicator ──────────────────

describe('classifyError — org-policy blocked (true positives)', () => {
  it('returns ORG_POLICY_BLOCKED when x-policy-block header is "true"', () => {
    assert.equal(
      classifyError(403, {}, { 'x-policy-block': 'true' }),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when x-policy-block header is "1"', () => {
    assert.equal(
      classifyError(403, {}, { 'x-policy-block': '1' }),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when x-policy-block header is "yes"', () => {
    assert.equal(
      classifyError(403, {}, { 'x-policy-block': 'yes' }),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('does NOT return ORG_POLICY_BLOCKED when x-policy-block header is "false"', () => {
    assert.notEqual(
      classifyError(403, {}, { 'x-policy-block': 'false' }),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when x-org-block header is "true"', () => {
    assert.equal(
      classifyError(403, {}, { 'x-org-block': 'true' }),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when x-saml-required header is "true"', () => {
    assert.equal(
      classifyError(403, {}, { 'x-saml-required': 'true' }),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when body contains "org_policy_block"', () => {
    assert.equal(
      classifyError(403, 'error: org_policy_block', {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when body contains "organization_policy"', () => {
    assert.equal(
      classifyError(403, { error: 'organization_policy' }, {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when body contains "policy_block"', () => {
    assert.equal(
      classifyError(403, { reason: 'policy_block' }, {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when body contains "blocked_by_policy"', () => {
    assert.equal(
      classifyError(403, 'blocked_by_policy', {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when body contains "saml_required"', () => {
    assert.equal(
      classifyError(403, { error: 'saml_required' }, {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when body contains "sso_required"', () => {
    assert.equal(
      classifyError(403, 'sso_required', {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('returns ORG_POLICY_BLOCKED when body contains "sso_enforcement"', () => {
    assert.equal(
      classifyError(403, { message: 'sso_enforcement' }, {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });

  it('indicator matching is case-insensitive in the body', () => {
    assert.equal(
      classifyError(403, 'Error: ORG_POLICY_BLOCK detected', {}),
      ERROR_TYPES.ORG_POLICY_BLOCKED
    );
  });
});

// ── NOT org-policy blocked — plain 401 / 403 must NOT trigger the message ────

describe('classifyError — non-org-policy errors (no misclassification)', () => {
  it('plain 403 with no indicator is FORBIDDEN, not ORG_POLICY_BLOCKED', () => {
    const result = classifyError(403, {}, {});
    assert.notEqual(result, ERROR_TYPES.ORG_POLICY_BLOCKED);
    assert.equal(result, ERROR_TYPES.FORBIDDEN);
  });

  it('plain 401 is SESSION_EXPIRED, not ORG_POLICY_BLOCKED', () => {
    const result = classifyError(401, {}, {});
    assert.notEqual(result, ERROR_TYPES.ORG_POLICY_BLOCKED);
    assert.equal(result, ERROR_TYPES.SESSION_EXPIRED);
  });

  it('401 with generic body is SESSION_EXPIRED', () => {
    const result = classifyError(401, { message: 'Unauthorized' }, {});
    assert.equal(result, ERROR_TYPES.SESSION_EXPIRED);
  });

  it('403 with "Access denied" body is FORBIDDEN, not ORG_POLICY_BLOCKED', () => {
    const result = classifyError(403, 'Access denied', {});
    assert.notEqual(result, ERROR_TYPES.ORG_POLICY_BLOCKED);
    assert.equal(result, ERROR_TYPES.FORBIDDEN);
  });

  it('403 with "feature flag disabled" body is FORBIDDEN', () => {
    const result = classifyError(403, 'feature flag disabled', {});
    assert.equal(result, ERROR_TYPES.FORBIDDEN);
  });

  it('403 with a CSP/frame-ancestors body is FORBIDDEN, not ORG_POLICY_BLOCKED', () => {
    const result = classifyError(403, 'frame-ancestors violation', {});
    assert.equal(result, ERROR_TYPES.FORBIDDEN);
  });

  it('404 is FEATURE_UNAVAILABLE', () => {
    assert.equal(classifyError(404, {}, {}), ERROR_TYPES.FEATURE_UNAVAILABLE);
  });

  it('410 is FEATURE_UNAVAILABLE', () => {
    assert.equal(classifyError(410, {}, {}), ERROR_TYPES.FEATURE_UNAVAILABLE);
  });

  it('status 0 (network failure) is NETWORK_ERROR', () => {
    assert.equal(classifyError(0, {}, {}), ERROR_TYPES.NETWORK_ERROR);
  });

  it('null status (fetch rejected before response) is NETWORK_ERROR', () => {
    assert.equal(classifyError(null, {}, {}), ERROR_TYPES.NETWORK_ERROR);
  });

  it('undefined status is NETWORK_ERROR', () => {
    assert.equal(classifyError(undefined, {}, {}), ERROR_TYPES.NETWORK_ERROR);
  });

  it('500 is UNKNOWN', () => {
    assert.equal(classifyError(500, {}, {}), ERROR_TYPES.UNKNOWN);
  });
});

// ── getErrorMessage ───────────────────────────────────────────────────────────

describe('getErrorMessage', () => {
  it('ORG_POLICY_BLOCKED message mentions "administrador"', () => {
    const msg = TwoFA.getErrorMessage(ERROR_TYPES.ORG_POLICY_BLOCKED);
    assert.ok(msg.toLowerCase().includes('administrador'),
      'org-policy message should include guidance to contact the admin');
  });

  it('SESSION_EXPIRED message mentions logging in again', () => {
    const msg = TwoFA.getErrorMessage(ERROR_TYPES.SESSION_EXPIRED);
    assert.ok(msg.toLowerCase().includes('sesión'),
      'session-expired message should mention the session');
  });

  it('returns a non-empty string for all known error types', () => {
    Object.values(ERROR_TYPES).forEach((type) => {
      const msg = TwoFA.getErrorMessage(type);
      assert.ok(typeof msg === 'string' && msg.length > 0,
        `Expected a non-empty message for type "${type}"`);
    });
  });

  it('falls back to UNKNOWN message for an unrecognised type', () => {
    const msg = TwoFA.getErrorMessage('bogus_type');
    assert.equal(msg, TwoFA.MESSAGES.unknown);
  });
});
