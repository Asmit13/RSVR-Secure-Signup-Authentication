# RSVR Technologies — Secure Sign-up and Authentication Solution

**Assignment:** Design a screen and detailed implementation plan for account creation using email or phone, date of birth and surname; sign-in through a six-digit code or device biometrics; one active device per account; and a one-hour lockout after five incorrect credentials.

**Proposed implementation:** Responsive web application + Node.js / Express API + SQLite persistence + WebAuthn passkeys.

---

## 1. Executive summary

The proposed experience is passwordless. A new user provides one verified contact method (email or phone), surname and date of birth. RSVR sends a six-digit one-time code to prove control of that contact method. After successful verification, the account is created and the user is signed in.

On subsequent visits, the user can sign in with either:

- A fresh six-digit code sent to the account's verified email address or mobile number; or
- A registered passkey, which asks the device's platform authenticator to verify the user locally (for example, Face ID, Touch ID or Windows Hello).

The server maintains exactly one non-revoked authenticated session per account. A successful sign-in on a second device revokes the earlier session before creating the new one. Five consecutive invalid authentication attempts lock the account identifier for one hour. OTPs and passkey assertions are counted against the same account-level failure policy.

## 2. User experience and screen design

The supplied interface is responsive and contains four states:

| State | User experience | Primary action |
|---|---|---|
| Sign in | Email or phone entry, with separate code and biometric options | Continue with a code / Face ID or biometrics |
| Create account | Surname, date of birth and email or international phone number | Create account |
| Verify | Six-digit code entry, destination hint and expiry guidance | Verify and continue |
| Security dashboard | Current session, enabled sign-in methods and active-device notice | Enable passkey / Sign out |

The layout uses a clear information hierarchy, visible security explanations, keyboard-friendly inputs, mobile breakpoints, inline validation feedback and a separate dashboard state. The biometric control is not presented as an ordinary password field; it invokes the browser's native authenticator prompt.

### Sign-up journey

1. User selects **Create account**.
2. User enters surname, date of birth and either an email address or phone number.
3. The application validates the fields. Phone numbers are normalized to E.164 format; email addresses are lower-cased and trimmed.
4. The server generates a cryptographically random six-digit OTP, stores only an HMAC of the code, and sends it to the selected contact method.
5. The user enters the code. It is valid for 10 minutes and can be used once.
6. On successful verification, the server creates the account, encrypts the date of birth, creates the single active session and sets a secure session cookie.
7. The user lands on the security dashboard, where a passkey can be registered.

### Sign-in journey — one-time code

1. User enters the registered email address or phone number.
2. The server checks the account lockout state and sends a new six-digit code.
3. The user enters the code before its 10-minute expiry.
4. A valid code is consumed. The server revokes any previous active session, creates a new one and signs the user in.

### Sign-in journey — biometrics / passkey

1. User enters the registered email address or phone number and chooses **Continue with Face ID / biometrics**.
2. The server returns a short-lived WebAuthn challenge and the user's registered credential IDs.
3. The browser asks the platform authenticator to verify the user locally.
4. The browser returns a signed assertion. The server verifies the challenge, origin, relying-party ID, credential public key, signature and user-verification flag.
5. A valid assertion updates the authenticator counter and creates a new single active session.

The biometric itself stays on the user's device. The application does not access, store or transmit a face image, fingerprint image or biometric template. A platform authenticator may use its supported local user-verification method, which can include a device PIN depending on the device and its settings.

## 3. Architecture

```text
BROWSER / RESPONSIVE USER INTERFACE
  Sign-up and sign-in forms | OTP verification | Security dashboard
  WebAuthn browser API (platform authenticator)
                     |
                     | Same-origin HTTPS + HttpOnly session cookie
                     v
NODE.JS / EXPRESS API
  Input validation and IP rate limits
  OTP challenge service --------------------> SMTP / Twilio SMS
  WebAuthn challenge and assertion verification
  Account lockout service | Single-session service
                     |
                     | Transactional database operations
                     v
SQLITE (SELF-CONTAINED ASSIGNMENT BUILD)
  users | otp_challenges | passkeys
  webauthn_challenges | sessions | security_state
```

### Technology choices

| Layer | Choice | Reason |
|---|---|---|
| UI | HTML, CSS and JavaScript bundled with Vite | Lightweight, responsive screen; no heavy UI framework needed for this focused flow |
| API | Node.js 22+ and Express | Straightforward HTTP API and mature middleware ecosystem |
| OTP | Node cryptographic random generator + HMAC | Random six-digit code; only a keyed digest is persisted |
| Email | Nodemailer over configured SMTP | Provider-neutral email delivery |
| SMS | Twilio REST API | International SMS delivery using E.164 numbers |
| Biometrics | WebAuthn / passkeys via SimpleWebAuthn | Standards-based local authenticator verification |
| Persistence | SQLite with transactions and a partial unique index | Self-contained assignment build with a database-enforced one-session invariant |

## 4. Security design and control mapping

### 4.1 Six-digit code protection

- Codes are generated with Node's cryptographically secure `randomInt`, not `Math.random`.
- Codes are padded to exactly six digits.
- The database stores `HMAC(OTP_PEPPER, challengeId + code)`, not the raw code.
- OTP expiry is 10 minutes.
- A code is marked consumed after successful verification and cannot be replayed.
- The API applies IP-based rate limits and a 60-second re-send cooldown.
- Local development may print the OTP to the server terminal only. The OTP is never returned in an API response. Production mode requires a delivery provider and does not log codes.

### 4.2 Biometrics through WebAuthn

Websites cannot directly read Face ID or fingerprint sensor data. The correct integration is WebAuthn: the browser invokes a platform authenticator, the authenticator performs local user verification and signs a server-provided challenge, and the server verifies the signature using the stored credential public key.

The implementation:

- Requires user verification for registration and authentication.
- Uses a platform authenticator preference for enrolment.
- Stores the credential ID, public key, counter and supported transports; no biometric data is stored.
- Validates the expected challenge, exact origin and relying-party ID.
- Expires each WebAuthn challenge after five minutes and consumes it after use.
- Updates the authenticator signature counter after successful authentication.

### 4.3 One active device / session

The database has a partial unique index on `sessions(user_id)` where `revoked_at IS NULL`. This makes it impossible to have two simultaneously non-revoked sessions for one account in the database.

When a new authentication succeeds, the server performs the following steps in one SQLite transaction:

1. Revoke any existing active session for that user.
2. Create a fresh random session token.
3. Store only an HMAC hash of the token.
4. Insert the new active session.

The browser receives the raw token only in a `HttpOnly`, `SameSite=Strict` cookie; the cookie is `Secure` in production. A revoked session fails the server-side session lookup on its next request. This implements one active authenticated session at a time, including when sign-in moves from one browser/device to another.

**Important scope distinction:** The control is on active authenticated sessions, not a claim of permanent hardware identity. Passkeys may be synchronized by a user's platform credential manager. Even then, only one server session per account can remain active.

### 4.4 Five failures → one-hour lockout

- The failure counter is keyed by normalized account identifier.
- Incorrect OTPs and invalid passkey assertions both count as failed credentials.
- The fifth consecutive failure sets `locked_until` to one hour in the future.
- While locked, OTP requests and passkey authentication requests are rejected with HTTP 423 (Locked).
- Once the hour expires, the failure counter resets.
- A successful authentication clears the counter.
- IP-based rate limits provide a separate layer against high-volume automated requests.

### 4.5 Personal data and session protection

- Date of birth is encrypted at rest using AES-256-GCM and a dedicated 32-byte key, including while it is held in a pending sign-up challenge; the challenge table never stores the raw date of birth.
- Session tokens are generated with a cryptographically secure random generator and stored only as HMAC hashes.
- API responses containing authentication or account data use `Cache-Control: no-store`.
- Security headers are provided by Helmet, the API rejects cross-origin mutation requests, and production cookies require HTTPS.
- No password is introduced because the requested sign-in methods are one-time codes and biometrics. The failed-credential policy applies consistently to those authentication mechanisms.

## 5. Data model

| Table | Important fields | Purpose |
|---|---|---|
| `users` | `id`, `identifier`, `identifier_type`, `surname`, `dob_cipher`, `webauthn_user_id` | Account profile; date of birth is encrypted |
| `otp_challenges` | `id`, `identifier`, `purpose`, `otp_hash`, `attempts`, `expires_at`, `consumed_at` | Single-use email/SMS verification challenges |
| `passkeys` | `credential_id`, `public_key`, `counter`, `transports_json`, `user_id` | Registered WebAuthn public credentials |
| `webauthn_challenges` | `id`, `user_id`, `purpose`, `challenge`, `expires_at`, `consumed_at` | Short-lived registration/authentication challenges |
| `sessions` | `id`, `user_id`, `token_hash`, `device_label`, `expires_at`, `revoked_at` | Enforces one active authenticated session |
| `security_state` | `identifier`, `failure_count`, `locked_until` | One-hour account lockout state |

## 6. API contract

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/auth/signup/request-code` | Validate profile fields and send a sign-up OTP |
| POST | `/api/auth/signup/verify-code` | Verify OTP, create account and session |
| POST | `/api/auth/login/request-code` | Send a sign-in OTP |
| POST | `/api/auth/login/verify-code` | Verify OTP and create session |
| POST | `/api/auth/passkey/options` | Create a WebAuthn authentication challenge |
| POST | `/api/auth/passkey/verify` | Verify passkey assertion and create session |
| POST | `/api/passkeys/registration/options` | Create passkey registration challenge for signed-in user |
| POST | `/api/passkeys/registration/verify` | Verify and save the passkey public credential |
| GET | `/api/me` | Return current user, session and passkey status |
| POST | `/api/auth/logout` | Revoke the current session |

## 7. Important user-facing edge cases

| Scenario | Expected response |
|---|---|
| Invalid email / phone format | Inline validation; no OTP is sent |
| Expired OTP | Ask the user to request a fresh code |
| Incorrect OTP, attempts remaining | Show an error and remaining attempt count |
| Fifth incorrect credential | Lock account for one hour; block both OTP and passkey authentication |
| OTP replay | Reject because the challenge has already been consumed |
| Passkey not enrolled | Explain that the user can sign in with a code and enable a passkey from Security settings |
| Browser does not support WebAuthn | Keep the OTP route available |
| New device signs in | Revoke the previous session and make the new one the only active session |
| Old device makes another API request | Return 401 because its server-side session is revoked |
| OTP delivery provider is not configured | Local mode logs to terminal; production returns an error and never discloses the code |

## 8. Test plan

The included automated test suite checks:

1. Email normalization and international phone normalization.
2. Six-digit OTP generation and keyed digest comparison.
3. Date-of-birth encryption/decryption and absence of plaintext in the stored value.
4. Lockout on the fifth failed attempt and reset after the one-hour window.
5. Replacement of an existing session by a new successful login, leaving exactly one active row.

Additional acceptance tests for a hosted deployment:

- Create one account with an email and another with a phone number.
- Verify correct and incorrect OTPs, expiry, replay prevention and re-send throttling.
- Enrol a passkey on a supported device and complete a fresh biometric/passkey sign-in.
- Attempt sign-in from a second browser and confirm the first browser is signed out on its next API request.
- Submit five wrong OTPs, then attempt both OTP and passkey sign-in before and after the hour elapses.
- Confirm production cookies are Secure / HttpOnly / SameSite=Strict and no OTP appears in API responses or production logs.

## 9. Local setup and production configuration

The project includes a complete runnable codebase. Use Node.js 22.12 or newer:

```bash
npm install
cp .env.example .env
npm run build
npm start
```

Open `http://localhost:4000`. In local mode, the OTP appears only in the server terminal. For real delivery, configure SMTP and/or Twilio credentials in `.env`.

For production, generate three different 32-byte secrets and set them as `SESSION_SECRET`, `OTP_PEPPER` and `PII_ENCRYPTION_KEY`. Set `NODE_ENV=production`, an HTTPS `APP_ORIGIN`, the matching hostname-only `RP_ID`, and `DEV_OTP=false`. A production WebAuthn relying party must run on the intended secure origin.

### Production scale-up recommendations

This assignment build uses SQLite so it can be reviewed and run without cloud infrastructure. Before a horizontally scaled production release:

- Migrate the same schema and constraints to PostgreSQL.
- Store session, OTP and lockout state in a shared transactional database.
- Use a shared Redis-backed rate-limit store across application instances.
- Add email/SMS provider webhooks, delivery monitoring, retry policies and abuse analytics.
- Add audit events for sign-in, passkey enrolment, session replacement and lockout, without recording OTP values or biometric data.
- Add account recovery, verified-contact changes, passkey revocation and administrative support procedures.
- Add backup, retention, key rotation and privacy-deletion procedures for personal data.

## 10. Deliverables

- `web/` — responsive application screen and client-side WebAuthn integration.
- `server/` — API, OTP delivery, WebAuthn verification, encryption, lockout and session controls.
- `tests/` — automated security-focused tests.
- `README.md` — setup and run guide.

The solution deliberately separates the user experience from the security boundary: the UI guides the user, while the server and database enforce verification, lockout and the single-session invariant.
