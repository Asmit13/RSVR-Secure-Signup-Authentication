import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { db, cleanupExpiredRecords } from './db.js';
import { deliverOtp } from './notifications.js';
import {
  assertNotLocked,
  clearFailedAttempts,
  createSession,
  encryptDob,
  getSessionByToken,
  hashOtp,
  makeOtp,
  maskedIdentifier,
  normaliseIdentifier,
  recordFailedAttempt,
  revokeSession,
  safeHashCompare,
  validateSignupPayload,
} from './security.js';

const app = express();
const PORT = Number(process.env.PORT || 4000);
const APP_ORIGIN = process.env.APP_ORIGIN || `http://localhost:${PORT}`;
const RP_NAME = process.env.RP_NAME || 'RSVR Secure Access';
const RP_ID = process.env.RP_ID || new URL(APP_ORIGIN).hostname;
const COOKIE_NAME = 'rsvr_session';
const OTP_TTL = 10 * 60 * 1000;
const WEBAUTHN_TTL = 5 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const here = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(here, '..', 'dist');

if (process.env.NODE_ENV === 'production') {
  for (const name of ['SESSION_SECRET', 'OTP_PEPPER', 'PII_ENCRYPTION_KEY']) {
    if (!/^[a-f\d]{64}$/i.test(process.env[name] || '')) {
      throw new Error(`${name} must be 32 random bytes encoded as 64 hexadecimal characters.`);
    }
  }
  app.set('trust proxy', 1);
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
}));
app.use(express.json({ limit: '32kb' }));
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many requests from this network. Please try again later.' },
});
const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many verification requests. Please try again later.' },
});

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== APP_ORIGIN) return res.status(403).json({ error: 'Request origin was not accepted.' });
  return next();
}
app.use('/api', requireSameOrigin);

function readCookie(req, name) {
  const cookieHeader = req.headers.cookie || '';
  for (const part of cookieHeader.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return null;
}

function setSessionCookie(res, token, expiresAt) {
  const maxAge = Math.max(0, expiresAt - Date.now());
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });
}

function currentSession(req) {
  return getSessionByToken(readCookie(req, COOKIE_NAME));
}

function requireAuth(req, res, next) {
  const session = currentSession(req);
  if (!session) {
    clearSessionCookie(res);
    return res.status(401).json({ error: 'Your session is no longer active. Please sign in again.' });
  }
  req.auth = session;
  return next();
}

function getUserByIdentifier(identifier) {
  return db.prepare('SELECT * FROM users WHERE identifier = ?').get(identifier);
}

function issueChallenge({ identifier, purpose, userId = null, signupPayload = null }) {
  const challengeId = randomUUID();
  const code = makeOtp();
  const now = Date.now();
  db.prepare(`
    INSERT INTO otp_challenges(id, identifier, purpose, otp_hash, user_id, signup_payload, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    challengeId,
    identifier,
    purpose,
    hashOtp(challengeId, code),
    userId,
    signupPayload ? JSON.stringify(signupPayload) : null,
    now + OTP_TTL,
    now,
  );
  return { challengeId, code };
}

function getValidOtpChallenge(challengeId, purpose) {
  const challenge = db.prepare('SELECT * FROM otp_challenges WHERE id = ? AND purpose = ?').get(challengeId, purpose);
  if (!challenge || challenge.consumed_at || challenge.expires_at <= Date.now()) {
    const error = new Error('This code has expired or is no longer valid. Request a new code.');
    error.status = 400;
    throw error;
  }
  if (challenge.attempts >= MAX_OTP_ATTEMPTS) {
    const error = new Error('This code has reached its attempt limit. Request a new code.');
    error.status = 423;
    throw error;
  }
  assertNotLocked(challenge.identifier);
  return challenge;
}

function markWrongOtp(challenge) {
  db.prepare('UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?').run(challenge.id);
  const lock = recordFailedAttempt(challenge.identifier);
  const attemptsLeft = Math.max(0, MAX_OTP_ATTEMPTS - (challenge.attempts + 1));
  return { lock, attemptsLeft };
}

function completeAuthentication(res, user, userAgent, identifier) {
  clearFailedAttempts(identifier);
  const session = createSession(user.id, userAgent);
  setSessionCookie(res, session.token, session.expiresAt);
  return {
    authenticated: true,
    user: {
      surname: user.surname,
      identifier: maskedIdentifier(user.identifier, user.identifier_type),
      identifierType: user.identifier_type,
    },
    session: { device: session.deviceLabel, expiresAt: session.expiresAt },
    securityNotice: 'Any previous active session for this account has been signed out.',
  };
}

// Sign-up: one identifier, surname and date of birth, verified through a one-time code.
app.post('/api/auth/signup/request-code', authLimiter, async (req, res, next) => {
  try {
    const type = req.body?.type;
    const identifier = normaliseIdentifier(req.body?.identifier, type);
    const payload = validateSignupPayload({ identifier, type, surname: req.body?.surname, dob: req.body?.dob });
    assertNotLocked(identifier);
    if (getUserByIdentifier(identifier)) return res.status(409).json({ error: 'An account already exists. Sign in instead.' });

    const mostRecent = db.prepare(`SELECT created_at FROM otp_challenges WHERE identifier = ? AND purpose = 'signup' ORDER BY created_at DESC LIMIT 1`).get(identifier);
    if (mostRecent && Date.now() - mostRecent.created_at < 60_000) {
      return res.status(429).json({ error: 'Please wait one minute before requesting another code.' });
    }

    const issued = issueChallenge({
      identifier,
      purpose: 'signup',
      // Keep even the temporary sign-up challenge free of plaintext date-of-birth data.
      signupPayload: { surname: payload.surname, dobCipher: encryptDob(payload.dob) },
    });
    try {
      await deliverOtp({ identifier, type, code: issued.code, purpose: 'signup' });
    } catch (deliveryError) {
      db.prepare('DELETE FROM otp_challenges WHERE id = ?').run(issued.challengeId);
      throw deliveryError;
    }
    return res.json({ challengeId: issued.challengeId, expiresInSeconds: OTP_TTL / 1000, message: `A six-digit verification code has been sent to ${maskedIdentifier(identifier, type)}.` });
  } catch (error) { return next(error); }
});

app.post('/api/auth/signup/verify-code', verifyLimiter, (req, res, next) => {
  try {
    const challenge = getValidOtpChallenge(req.body?.challengeId, 'signup');
    const code = String(req.body?.code ?? '').trim();
    if (!/^\d{6}$/.test(code) || !safeHashCompare(challenge.otp_hash, hashOtp(challenge.id, code))) {
      const { lock, attemptsLeft } = markWrongOtp(challenge);
      return res.status(lock.locked ? 423 : 400).json({
        error: lock.locked ? 'Five unsuccessful attempts reached. This account is locked for one hour.' : 'The code is incorrect.',
        attemptsLeft,
      });
    }

    const createUserAndSession = db.transaction(() => {
      const latest = db.prepare('SELECT * FROM otp_challenges WHERE id = ?').get(challenge.id);
      if (!latest || latest.consumed_at || latest.expires_at <= Date.now()) throw Object.assign(new Error('This code has already been used or expired.'), { status: 400 });
      if (getUserByIdentifier(challenge.identifier)) throw Object.assign(new Error('An account already exists. Sign in instead.'), { status: 409 });
      const payload = JSON.parse(challenge.signup_payload || '{}');
      const user = {
        id: randomUUID(),
        identifier: challenge.identifier,
        identifier_type: challenge.identifier.includes('@') ? 'email' : 'phone',
        surname: payload.surname,
        dob_cipher: payload.dobCipher,
        webauthn_user_id: randomUUID(),
        created_at: Date.now(),
      };
      db.prepare(`INSERT INTO users(id, identifier, identifier_type, surname, dob_cipher, webauthn_user_id, created_at)
        VALUES (@id, @identifier, @identifier_type, @surname, @dob_cipher, @webauthn_user_id, @created_at)`).run(user);
      db.prepare('UPDATE otp_challenges SET consumed_at = ? WHERE id = ?').run(Date.now(), challenge.id);
      return user;
    });
    const user = createUserAndSession();
    const response = completeAuthentication(res, user, req.get('user-agent') || 'Unknown device', challenge.identifier);
    return res.status(201).json(response);
  } catch (error) { return next(error); }
});

// Sign-in with one-time code. The response does not disclose whether an unknown identifier exists.
app.post('/api/auth/login/request-code', authLimiter, async (req, res, next) => {
  try {
    const type = req.body?.type;
    const identifier = normaliseIdentifier(req.body?.identifier, type);
    if (type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(identifier)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (type === 'phone' && !/^\+[1-9]\d{7,14}$/.test(identifier)) return res.status(400).json({ error: 'Enter a phone number in international format, e.g. +919876543210.' });
    assertNotLocked(identifier);
    const user = getUserByIdentifier(identifier);
    if (!user) return res.status(200).json({ message: 'If an account exists for this detail, a code has been sent.' });

    const mostRecent = db.prepare(`SELECT created_at FROM otp_challenges WHERE identifier = ? AND purpose = 'login' ORDER BY created_at DESC LIMIT 1`).get(identifier);
    if (mostRecent && Date.now() - mostRecent.created_at < 60_000) return res.status(429).json({ error: 'Please wait one minute before requesting another code.' });

    const issued = issueChallenge({ identifier, purpose: 'login', userId: user.id });
    try {
      await deliverOtp({ identifier, type, code: issued.code, purpose: 'login' });
    } catch (deliveryError) {
      db.prepare('DELETE FROM otp_challenges WHERE id = ?').run(issued.challengeId);
      throw deliveryError;
    }
    return res.json({ challengeId: issued.challengeId, expiresInSeconds: OTP_TTL / 1000, message: `A six-digit sign-in code has been sent to ${maskedIdentifier(identifier, type)}.` });
  } catch (error) { return next(error); }
});

app.post('/api/auth/login/verify-code', verifyLimiter, (req, res, next) => {
  try {
    const challenge = getValidOtpChallenge(req.body?.challengeId, 'login');
    const code = String(req.body?.code ?? '').trim();
    if (!/^\d{6}$/.test(code) || !safeHashCompare(challenge.otp_hash, hashOtp(challenge.id, code))) {
      const { lock, attemptsLeft } = markWrongOtp(challenge);
      return res.status(lock.locked ? 423 : 400).json({
        error: lock.locked ? 'Five unsuccessful attempts reached. This account is locked for one hour.' : 'The code is incorrect.',
        attemptsLeft,
      });
    }

    const consume = db.prepare('UPDATE otp_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL').run(Date.now(), challenge.id);
    if (!consume.changes) return res.status(409).json({ error: 'This code has already been used.' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.user_id);
    if (!user) return res.status(400).json({ error: 'Account not found. Please sign up.' });
    return res.json(completeAuthentication(res, user, req.get('user-agent') || 'Unknown device', challenge.identifier));
  } catch (error) { return next(error); }
});

// Passwordless biometric sign-in through a platform authenticator (Face ID, Touch ID, Windows Hello, etc.).
app.post('/api/auth/passkey/options', authLimiter, async (req, res, next) => {
  try {
    const type = req.body?.type;
    const identifier = normaliseIdentifier(req.body?.identifier, type);
    assertNotLocked(identifier);
    const user = getUserByIdentifier(identifier);
    const unavailable = { error: 'Passkey sign-in is unavailable for these details. Use a verification code or check the account information.' };
    if (!user) return res.status(404).json(unavailable);
    const passkeys = db.prepare('SELECT credential_id, transports_json FROM passkeys WHERE user_id = ?').all(user.id);
    if (!passkeys.length) return res.status(404).json(unavailable);

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: passkeys.map((item) => ({ id: item.credential_id, transports: JSON.parse(item.transports_json) })),
      userVerification: 'required',
    });
    const id = randomUUID();
    db.prepare(`INSERT INTO webauthn_challenges(id, user_id, purpose, challenge, expires_at, created_at)
      VALUES (?, ?, 'authentication', ?, ?, ?)`).run(id, user.id, options.challenge, Date.now() + WEBAUTHN_TTL, Date.now());
    return res.json({ challengeId: id, options });
  } catch (error) { return next(error); }
});

app.post('/api/auth/passkey/verify', verifyLimiter, async (req, res, next) => {
  try {
    const challengeId = String(req.body?.challengeId || '');
    const response = req.body?.response;
    const challenge = db.prepare(`SELECT wc.*, u.identifier, u.identifier_type
      FROM webauthn_challenges wc JOIN users u ON u.id = wc.user_id
      WHERE wc.id = ? AND wc.purpose = 'authentication'`).get(challengeId);
    if (!challenge || challenge.consumed_at || challenge.expires_at <= Date.now()) return res.status(400).json({ error: 'The biometric request expired. Try again.' });
    assertNotLocked(challenge.identifier);
    // Atomically claim the challenge before cryptographic verification to prevent parallel replay.
    const claim = db.prepare(`UPDATE webauthn_challenges SET consumed_at = ?
      WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`).run(Date.now(), challenge.id, Date.now());
    if (!claim.changes) return res.status(409).json({ error: 'This biometric request has already been used. Try again.' });
    const passkey = db.prepare('SELECT * FROM passkeys WHERE user_id = ? AND credential_id = ?').get(challenge.user_id, response?.id);
    if (!passkey) {
      const lock = recordFailedAttempt(challenge.identifier);
      return res.status(lock.locked ? 423 : 401).json({ error: lock.locked ? 'Five unsuccessful attempts reached. This account is locked for one hour.' : 'The biometric credential was not recognised.' });
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: APP_ORIGIN,
        expectedRPID: RP_ID,
        credential: {
          id: passkey.credential_id,
          publicKey: new Uint8Array(passkey.public_key),
          counter: passkey.counter,
          transports: JSON.parse(passkey.transports_json),
        },
        requireUserVerification: true,
      });
    } catch {
      const lock = recordFailedAttempt(challenge.identifier);
      return res.status(lock.locked ? 423 : 401).json({ error: lock.locked ? 'Five unsuccessful attempts reached. This account is locked for one hour.' : 'Biometric verification failed. Try again or use a one-time code.' });
    }

    if (!verification.verified) {
      const lock = recordFailedAttempt(challenge.identifier);
      return res.status(lock.locked ? 423 : 401).json({ error: 'Biometric verification failed.' });
    }
    db.prepare('UPDATE passkeys SET counter = ? WHERE id = ?').run(verification.authenticationInfo.newCounter, passkey.id);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.user_id);
    return res.json(completeAuthentication(res, user, req.get('user-agent') || 'Unknown device', challenge.identifier));
  } catch (error) { return next(error); }
});

// Enrol a passkey from an already authenticated session.
app.post('/api/passkeys/registration/options', requireAuth, async (req, res, next) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth.user_id);
    const current = db.prepare('SELECT credential_id, transports_json FROM passkeys WHERE user_id = ?').all(user.id);
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: new TextEncoder().encode(user.webauthn_user_id),
      userName: user.identifier,
      userDisplayName: `${user.surname} (${maskedIdentifier(user.identifier, user.identifier_type)})`,
      attestationType: 'none',
      excludeCredentials: current.map((item) => ({ id: item.credential_id, transports: JSON.parse(item.transports_json) })),
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'required',
      },
    });
    const id = randomUUID();
    db.prepare(`INSERT INTO webauthn_challenges(id, user_id, purpose, challenge, expires_at, created_at)
      VALUES (?, ?, 'registration', ?, ?, ?)`).run(id, user.id, options.challenge, Date.now() + WEBAUTHN_TTL, Date.now());
    return res.json({ challengeId: id, options });
  } catch (error) { return next(error); }
});

app.post('/api/passkeys/registration/verify', requireAuth, async (req, res, next) => {
  try {
    const challengeId = String(req.body?.challengeId || '');
    const response = req.body?.response;
    const challenge = db.prepare(`SELECT * FROM webauthn_challenges
      WHERE id = ? AND user_id = ? AND purpose = 'registration'`).get(challengeId, req.auth.user_id);
    if (!challenge || challenge.consumed_at || challenge.expires_at <= Date.now()) return res.status(400).json({ error: 'The passkey registration expired. Start again.' });
    const claim = db.prepare(`UPDATE webauthn_challenges SET consumed_at = ?
      WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`).run(Date.now(), challenge.id, Date.now());
    if (!claim.changes) return res.status(409).json({ error: 'This passkey request has already been used. Start again.' });

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: APP_ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.registrationInfo) return res.status(400).json({ error: 'The authenticator could not be verified.' });

    const info = verification.registrationInfo;
    const credential = info.credential;
    db.prepare(`INSERT INTO passkeys(id, user_id, credential_id, public_key, counter, transports_json, device_type, backed_up, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), req.auth.user_id, credential.id, Buffer.from(credential.publicKey), credential.counter,
        JSON.stringify(credential.transports || []), info.credentialDeviceType, info.credentialBackedUp ? 1 : 0, Date.now());
    return res.status(201).json({ registered: true, message: 'Biometric sign-in is now enabled for this account.' });
  } catch (error) { return next(error); }
});

app.get('/api/me', requireAuth, (req, res) => {
  const passkeyCount = db.prepare('SELECT COUNT(*) AS count FROM passkeys WHERE user_id = ?').get(req.auth.user_id).count;
  return res.json({
    user: {
      surname: req.auth.surname,
      identifier: maskedIdentifier(req.auth.identifier, req.auth.identifier_type),
      identifierType: req.auth.identifier_type,
    },
    session: { device: req.auth.device_label, expiresAt: req.auth.expires_at },
    security: { passkeyEnabled: passkeyCount > 0, passkeyCount, activeDeviceLimit: 1 },
  });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = readCookie(req, COOKIE_NAME);
  revokeSession(token);
  clearSessionCookie(res);
  return res.json({ signedOut: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found.' }));

app.use(express.static(distDir, { index: false, maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(distDir, 'index.html'), (error) => {
    if (error) res.status(503).send('Frontend is not built yet. Run npm run build.');
  });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = Number(error.status) || 500;
  if (status >= 500) console.error('[RSVR API]', error.message);
  return res.status(status).json({ error: status >= 500 ? 'Something went wrong. Please try again.' : error.message });
});

cleanupExpiredRecords();
setInterval(cleanupExpiredRecords, 60 * 60 * 1000).unref();
app.listen(PORT, () => {
  console.info(`RSVR Secure Access running at ${APP_ORIGIN}`);
  console.info(`WebAuthn RP ID: ${RP_ID}`);
  if (process.env.NODE_ENV !== 'production' && process.env.DEV_OTP === 'true') {
    console.info('Local OTP mode is enabled. Verification codes are printed to this terminal only.');
  }
});
