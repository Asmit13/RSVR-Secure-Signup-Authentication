import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  timingSafeEqual,
  randomUUID,
} from 'node:crypto';
import { db } from './db.js';

const HOUR = 60 * 60 * 1000;
const SESSION_TTL = 30 * 24 * HOUR;

const sessionSecret = process.env.SESSION_SECRET || 'local-development-session-secret-change-before-production';
const otpPepper = process.env.OTP_PEPPER || 'local-development-otp-pepper-change-before-production';
const configuredKey = process.env.PII_ENCRYPTION_KEY;
const encryptionKey = configuredKey && /^[a-f\d]{64}$/i.test(configuredKey)
  ? Buffer.from(configuredKey, 'hex')
  : createHash('sha256').update('local-development-pii-key-change-before-production').digest();

export function normaliseIdentifier(value, type) {
  const raw = String(value ?? '').trim();
  if (type === 'email') return raw.toLowerCase();
  if (type === 'phone') return raw.replace(/[\s().-]/g, '');
  throw new Error('Choose email or phone.');
}

export function makeOtp() {
  return String(randomInt(0, 1_000_000)).padStart(6, '0');
}

export function hashOtp(challengeId, code) {
  return createHmac('sha256', otpPepper).update(`${challengeId}:${code}`).digest('hex');
}

export function safeHashCompare(expected, actual) {
  const a = Buffer.from(String(expected), 'hex');
  const b = Buffer.from(String(actual), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export function encryptDob(dob) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(dob, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map((part) => part.toString('base64url')).join('.');
}

export function decryptDob(payload) {
  const [ivText, tagText, cipherText] = payload.split('.');
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(cipherText, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

export function getLockState(identifier) {
  const state = db.prepare('SELECT failure_count, locked_until FROM security_state WHERE identifier = ?').get(identifier);
  if (!state) return { locked: false, failureCount: 0, retryAfterMs: 0 };
  const now = Date.now();
  if (state.locked_until && state.locked_until <= now) {
    db.prepare('DELETE FROM security_state WHERE identifier = ?').run(identifier);
    return { locked: false, failureCount: 0, retryAfterMs: 0 };
  }
  return {
    locked: Boolean(state.locked_until && state.locked_until > now),
    failureCount: state.failure_count,
    retryAfterMs: state.locked_until ? Math.max(0, state.locked_until - now) : 0,
  };
}

export function assertNotLocked(identifier) {
  const state = getLockState(identifier);
  if (state.locked) {
    const minutes = Math.max(1, Math.ceil(state.retryAfterMs / 60_000));
    const error = new Error(`Too many unsuccessful attempts. Try again in about ${minutes} minute(s).`);
    error.status = 423;
    throw error;
  }
}

export function recordFailedAttempt(identifier) {
  const now = Date.now();
  const state = db.prepare('SELECT failure_count, locked_until FROM security_state WHERE identifier = ?').get(identifier);
  if (state?.locked_until && state.locked_until > now) return getLockState(identifier);

  const previous = state && (!state.locked_until) ? state.failure_count
    : (state?.locked_until && state.locked_until > now ? state.failure_count : 0);
  const next = previous + 1;
  const lockedUntil = next >= 5 ? now + HOUR : null;
  db.prepare(`
    INSERT INTO security_state(identifier, failure_count, locked_until, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(identifier) DO UPDATE SET
      failure_count = excluded.failure_count,
      locked_until = excluded.locked_until,
      updated_at = excluded.updated_at
  `).run(identifier, next, lockedUntil, now);
  return getLockState(identifier);
}

export function clearFailedAttempts(identifier) {
  db.prepare('DELETE FROM security_state WHERE identifier = ?').run(identifier);
}

export function createSession(userId, userAgent = 'Unknown device') {
  const id = randomUUID();
  const token = randomBytes(32).toString('base64url');
  const tokenHash = createHmac('sha256', sessionSecret).update(token).digest('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_TTL;
  const deviceLabel = String(userAgent).slice(0, 180) || 'Unknown device';

  const create = db.transaction(() => {
    // A successful new sign-in takes ownership of the single active session slot.
    db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(now, userId);
    db.prepare(`
      INSERT INTO sessions(id, user_id, token_hash, device_label, created_at, last_seen_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, userId, tokenHash, deviceLabel, now, now, expiresAt);
  });
  create.immediate();
  return { token, expiresAt, deviceLabel };
}

export function hashSessionToken(token) {
  return createHmac('sha256', sessionSecret).update(token).digest('hex');
}

export function getSessionByToken(token) {
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  const now = Date.now();
  const session = db.prepare(`
    SELECT s.id AS session_id, s.user_id, s.device_label, s.expires_at,
           u.identifier, u.identifier_type, u.surname
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?
  `).get(tokenHash, now);
  if (session) db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now, session.session_id);
  return session || null;
}

export function revokeSession(token) {
  if (!token) return;
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
    .run(Date.now(), hashSessionToken(token));
}

export function maskedIdentifier(identifier, type) {
  if (type === 'email') {
    const [name, domain] = identifier.split('@');
    return `${name.slice(0, 1)}${'*'.repeat(Math.max(2, name.length - 1))}@${domain}`;
  }
  return `${'*'.repeat(Math.max(0, identifier.length - 4))}${identifier.slice(-4)}`;
}

export function validateSignupPayload({ identifier, type, surname, dob }) {
  const cleanSurname = String(surname ?? '').trim().replace(/\s+/g, ' ');
  if (!cleanSurname || cleanSurname.length < 2 || cleanSurname.length > 60) {
    throw Object.assign(new Error('Surname must be between 2 and 60 characters.'), { status: 400 });
  }
  if (type === 'email') {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(identifier)) {
      throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
    }
  } else if (type === 'phone') {
    if (!/^\+[1-9]\d{7,14}$/.test(identifier)) {
      throw Object.assign(new Error('Enter a phone number in international format, e.g. +919876543210.'), { status: 400 });
    }
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(dob))) {
    throw Object.assign(new Error('Enter your date of birth.'), { status: 400 });
  }
  const date = new Date(`${dob}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== dob || date > new Date()) {
    throw Object.assign(new Error('Enter a valid date of birth that is not in the future.'), { status: 400 });
  }
  return { surname: cleanSurname, dob };
}
