# RSVR Secure Access — Assignment Submission

A responsive, passwordless authentication experience for RSVR Technologies. It implements email/SMS verification codes, platform passkeys for biometric sign-in, a single-active-session rule, and account lockout after five failed credential attempts.

## What is included

- `web/` — responsive sign-in, sign-up, verification-code and security dashboard screens.
- `server/` — Express API, SQLite persistence, email/SMS delivery, session management and WebAuthn verification.
- `tests/` — automated checks for OTP generation, personal-data encryption, lockout and single-session enforcement.
- `SOLUTION.md` — detailed product plan, architecture, security controls, API map and test plan.
- `.env.example` — configuration template. No production secrets are included.

## Requirements

- Node.js 22.12 or newer.
- npm.
- SMTP details to deliver email codes in a live environment.
- Twilio credentials and a sender number to deliver SMS codes in a live environment.
- HTTPS and a production domain for production WebAuthn / passkeys.

## Run locally

```bash
npm install
cp .env.example .env
npm run build
npm start
```

Open `http://localhost:4000`.

For local assessment, `DEV_OTP=true` prints codes to the server terminal. The code is deliberately not returned by the API or shown in the browser response. Email and SMS delivery are used automatically when their respective providers are configured.

## Configure delivery

For email, set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS` and `EMAIL_FROM` in `.env`.

For phone, set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` and `TWILIO_FROM_NUMBER`. Phone numbers must be in E.164 format, such as `+919876543210`.

## Configure security before deployment

Generate three different random secrets:

```bash
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
```

Set the outputs as `SESSION_SECRET`, `OTP_PEPPER` and `PII_ENCRYPTION_KEY`. Set:

- `NODE_ENV=production`
- `APP_ORIGIN=https://your-real-hostname.example` (no trailing slash)
- `RP_ID=your-real-hostname.example` (hostname only, no scheme or port)
- `DEV_OTP=false`

The production server refuses to start if the three 32-byte secrets are missing or malformed. Use HTTPS, protect the `.env` file, restrict database-file permissions, and place the service behind a correctly configured TLS reverse proxy. The application trusts one reverse proxy in production.

## Run checks

```bash
npm test
```

## Important implementation notes

1. **Biometrics:** The browser uses WebAuthn passkeys. Face ID, Touch ID, Windows Hello or an equivalent local authenticator verifies the user on the device. The server receives a signed assertion and verifies it against the registered public key; it never receives biometric images, templates or fingerprint data. Depending on the platform, the authenticator may allow a device PIN as its user-verification method.
2. **One active device:** This build enforces one active authenticated session per account. A successful login from a second device revokes the previous session. The session is represented by a random, HTTP-only cookie, while only its HMAC hash is stored in SQLite. This controls concurrent authenticated sessions; it does not claim to identify immutable physical hardware.
3. **Lockout:** Invalid OTP submissions and invalid passkey assertions share one account-level counter. The fifth consecutive failure locks that account identifier for one hour. A successful authentication clears the counter.
4. **Local database:** SQLite is used to keep the assignment self-contained and easy to run. For a multi-instance production deployment, move the schema to PostgreSQL and use a shared transactional store for sessions, challenges and lockout state. Use a shared rate-limit store such as Redis as well.
5. **Delivery:** Local development logs codes only to the server terminal. Production requires a real configured delivery provider; it will not silently fall back to logging codes.

See `SOLUTION.md` for the full design rationale and test cases.
