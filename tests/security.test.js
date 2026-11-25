import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tempDir = mkdtempSync(path.join(os.tmpdir(), 'rsvr-auth-test-'));
process.env.DB_PATH = path.join(tempDir, 'test.sqlite');
process.env.SESSION_SECRET = 'test-session-secret-with-enough-entropy';
process.env.OTP_PEPPER = 'test-otp-pepper-with-enough-entropy';

const [{ db }, security] = await Promise.all([
  import('../server/db.js'),
  import('../server/security.js'),
]);

test('normalises email and phone identifiers', () => {
  assert.equal(security.normaliseIdentifier('  PERSON@Example.COM ', 'email'), 'person@example.com');
  assert.equal(security.normaliseIdentifier('+91 98765-43210', 'phone'), '+919876543210');
});

test('creates six digit codes and compares their HMAC safely', () => {
  const challengeId = randomUUID();
  const code = security.makeOtp();
  assert.match(code, /^\d{6}$/);
  const hash = security.hashOtp(challengeId, code);
  assert.equal(security.safeHashCompare(hash, security.hashOtp(challengeId, code)), true);
  assert.equal(security.safeHashCompare(hash, security.hashOtp(challengeId, '000000')), false);
});

test('encrypts and decrypts date of birth without storing it in plaintext', () => {
  const dob = '1998-04-15';
  const ciphertext = security.encryptDob(dob);
  assert.equal(ciphertext.includes(dob), false);
  assert.equal(security.decryptDob(ciphertext), dob);
});

test('locks after five failed credentials and resets after one hour', () => {
  const identifier = `lock-${randomUUID()}@example.test`;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const state = security.recordFailedAttempt(identifier);
    assert.equal(state.locked, false);
  }
  const locked = security.recordFailedAttempt(identifier);
  assert.equal(locked.locked, true);
  assert.ok(locked.retryAfterMs > 0);

  db.prepare('UPDATE security_state SET locked_until = ? WHERE identifier = ?').run(Date.now() - 1, identifier);
  const afterExpiry = security.recordFailedAttempt(identifier);
  assert.equal(afterExpiry.locked, false);
  assert.equal(afterExpiry.failureCount, 1);
});

test('a new successful login replaces the previous active session', () => {
  const userId = randomUUID();
  db.prepare(`INSERT INTO users(id, identifier, identifier_type, surname, dob_cipher, webauthn_user_id, created_at)
    VALUES (?, ?, 'email', 'Tester', ?, ?, ?)`)
    .run(userId, `${userId}@example.test`, security.encryptDob('1990-01-01'), randomUUID(), Date.now());

  const first = security.createSession(userId, 'First browser');
  assert.ok(security.getSessionByToken(first.token));
  const second = security.createSession(userId, 'Second browser');
  assert.equal(security.getSessionByToken(first.token), null);
  assert.ok(security.getSessionByToken(second.token));
  const active = db.prepare('SELECT COUNT(*) AS count FROM sessions WHERE user_id = ? AND revoked_at IS NULL').get(userId);
  assert.equal(active.count, 1);
});

test.after(() => {
  db.close();
  rmSync(tempDir, { recursive: true, force: true });
});
