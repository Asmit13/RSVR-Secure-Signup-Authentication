import { startAuthentication, startRegistration, browserSupportsWebAuthn } from '@simplewebauthn/browser';
import './styles.css';

const $ = (selector) => document.querySelector(selector);
const elements = {
  authView: $('#auth-view'), dashboardView: $('#dashboard-view'),
  loginForm: $('#login-form'), signupForm: $('#signup-form'), codeForm: $('#code-form'),
  loginTab: $('#login-tab'), signupTab: $('#signup-tab'),
  authHeading: $('#auth-heading'), authSubheading: $('#auth-subheading'),
  authMessage: $('#auth-message'), dashboardMessage: $('#dashboard-message'),
};

let mode = 'login';
let pendingChallenge = null;
let pendingIdentifier = null;
let pendingType = null;
let pendingPurpose = null;

function inferType(identifier) {
  return identifier.trim().includes('@') ? 'email' : 'phone';
}

function setMessage(target, text, kind = 'error') {
  target.textContent = text;
  target.className = `message show ${kind}`;
}

function clearMessage(target) {
  target.textContent = '';
  target.className = 'message';
}

function setBusy(button, busy, label) {
  if (busy) {
    button.dataset.originalText = button.innerHTML;
    button.disabled = true;
    button.textContent = label || 'Please wait…';
  } else {
    button.disabled = false;
    if (button.dataset.originalText) button.innerHTML = button.dataset.originalText;
  }
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Something went wrong. Please try again.');
  return data;
}

function showMode(nextMode) {
  mode = nextMode;
  pendingChallenge = null;
  elements.loginForm.classList.toggle('hidden', nextMode !== 'login');
  elements.signupForm.classList.toggle('hidden', nextMode !== 'signup');
  elements.codeForm.classList.add('hidden');
  elements.loginTab.classList.toggle('active', nextMode === 'login');
  elements.signupTab.classList.toggle('active', nextMode === 'signup');
  elements.loginTab.setAttribute('aria-selected', String(nextMode === 'login'));
  elements.signupTab.setAttribute('aria-selected', String(nextMode === 'signup'));
  elements.authHeading.textContent = nextMode === 'login' ? 'Sign in to continue.' : 'Create your account.';
  elements.authSubheading.textContent = nextMode === 'login'
    ? "Your account, protected by a code or your device's biometrics."
    : 'A few details are all we need to get you started.';
  clearMessage(elements.authMessage);
}

elements.loginTab.addEventListener('click', () => showMode('login'));
elements.signupTab.addEventListener('click', () => showMode('signup'));

async function requestCode({ identifier, type, purpose, payload, button }) {
  const endpoint = purpose === 'signup' ? '/api/auth/signup/request-code' : '/api/auth/login/request-code';
  setBusy(button, true, 'Sending code…');
  clearMessage(elements.authMessage);
  try {
    const data = await api(endpoint, { method: 'POST', body: JSON.stringify({ identifier, type, ...payload }) });
    if (!data.challengeId) {
      setMessage(elements.authMessage, data.message || 'If an account exists for this detail, a code has been sent.', 'success');
      return;
    }
    pendingChallenge = data.challengeId;
    pendingIdentifier = identifier;
    pendingType = type;
    pendingPurpose = purpose;
    elements.loginForm.classList.add('hidden');
    elements.signupForm.classList.add('hidden');
    elements.codeForm.classList.remove('hidden');
    $('#code-destination').textContent = data.message || 'A six-digit code has been sent to your registered contact.';
    $('#verification-code').value = '';
    $('#verification-code').focus();
    elements.authHeading.textContent = 'One last step.';
    elements.authSubheading.textContent = 'Verify that you own this email address or mobile number.';
    clearMessage(elements.authMessage);
  } catch (error) {
    setMessage(elements.authMessage, error.message);
  } finally {
    setBusy(button, false);
  }
}

elements.loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const identifier = $('#login-identifier').value.trim();
  if (!identifier) return;
  await requestCode({ identifier, type: inferType(identifier), purpose: 'login', button: $('#send-login-code') });
});

elements.signupForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const identifier = $('#signup-identifier').value.trim();
  const payload = { surname: $('#signup-surname').value.trim(), dob: $('#signup-dob').value };
  if (!identifier || !payload.surname || !payload.dob) return;
  await requestCode({ identifier, type: inferType(identifier), purpose: 'signup', payload, button: $('#send-signup-code') });
});

$('#back-to-details').addEventListener('click', () => {
  pendingChallenge = null;
  elements.codeForm.classList.add('hidden');
  (mode === 'signup' ? elements.signupForm : elements.loginForm).classList.remove('hidden');
  elements.authHeading.textContent = mode === 'login' ? 'Sign in to continue.' : 'Create your account.';
  elements.authSubheading.textContent = mode === 'login'
    ? "Your account, protected by a code or your device's biometrics."
    : 'A few details are all we need to get you started.';
  clearMessage(elements.authMessage);
});

elements.codeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const code = $('#verification-code').value.trim();
  if (!/^\d{6}$/.test(code) || !pendingChallenge) {
    setMessage(elements.authMessage, 'Enter the six-digit code we sent you.');
    return;
  }
  const button = $('#verify-code');
  setBusy(button, true, 'Verifying…');
  clearMessage(elements.authMessage);
  try {
    const endpoint = pendingPurpose === 'signup' ? '/api/auth/signup/verify-code' : '/api/auth/login/verify-code';
    const data = await api(endpoint, { method: 'POST', body: JSON.stringify({ challengeId: pendingChallenge, code }) });
    await loadDashboard(data);
  } catch (error) {
    setMessage(elements.authMessage, error.message);
  } finally {
    setBusy(button, false);
  }
});

$('#passkey-login').addEventListener('click', async () => {
  const identifier = $('#login-identifier').value.trim();
  if (!identifier) {
    setMessage(elements.authMessage, 'Enter your email or phone number first, then choose biometrics.');
    $('#login-identifier').focus();
    return;
  }
  if (!browserSupportsWebAuthn()) {
    setMessage(elements.authMessage, 'This browser does not support passkeys. Use a one-time code instead.');
    return;
  }
  const button = $('#passkey-login');
  setBusy(button, true, 'Verifying with your device…');
  clearMessage(elements.authMessage);
  try {
    const type = inferType(identifier);
    const challenge = await api('/api/auth/passkey/options', { method: 'POST', body: JSON.stringify({ identifier, type }) });
    // Invoke the platform authenticator from the user's click flow. The device handles biometrics locally.
    const response = await startAuthentication({ optionsJSON: challenge.options });
    const result = await api('/api/auth/passkey/verify', {
      method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, response }),
    });
    await loadDashboard(result);
  } catch (error) {
    setMessage(elements.authMessage, error.message || 'Biometric sign-in was cancelled. You can use a one-time code.');
  } finally {
    setBusy(button, false);
  }
});

async function loadDashboard(authResult = null) {
  // Fetch the canonical session profile after authentication so that passkey state is always current.
  const data = await api('/api/me');
  const user = data.user;
  const session = data.session || {};
  const security = data.security || {};
  $('#avatar-initial').textContent = (user.surname || 'R').slice(0, 1).toUpperCase();
  $('#dashboard-heading').textContent = `Welcome, ${user.surname}.`;
  $('#account-identifier').textContent = `${user.identifier} · ${user.identifierType}`;
  $('#session-notice').textContent = authResult?.securityNotice || 'This is your only active session.';
  $('#device-name').textContent = session.device || 'This browser';
  $('#passkey-status').textContent = security.passkeyEnabled
    ? `${security.passkeyCount} passkey${security.passkeyCount === 1 ? '' : 's'} registered`
    : 'Not enabled on this account';
  $('#enable-passkey').textContent = security.passkeyEnabled ? 'Add another' : 'Enable';
  elements.authView.classList.add('hidden');
  elements.dashboardView.classList.remove('hidden');
  clearMessage(elements.dashboardMessage);
}

$('#enable-passkey').addEventListener('click', async () => {
  if (!browserSupportsWebAuthn()) {
    setMessage(elements.dashboardMessage, 'This browser does not support WebAuthn passkeys.');
    return;
  }
  const button = $('#enable-passkey');
  setBusy(button, true, 'Setting up…');
  clearMessage(elements.dashboardMessage);
  let passkeyAdded = false;
  try {
    const challenge = await api('/api/passkeys/registration/options', { method: 'POST', body: '{}' });
    const response = await startRegistration({ optionsJSON: challenge.options });
    const result = await api('/api/passkeys/registration/verify', {
      method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, response }),
    });
    const fresh = await api('/api/me');
    passkeyAdded = Boolean(fresh.security?.passkeyEnabled);
    await loadDashboard(fresh);
    setMessage(elements.dashboardMessage, result.message, 'success');
  } catch (error) {
    setMessage(elements.dashboardMessage, error.message || 'Passkey setup could not be completed.');
  } finally {
    setBusy(button, false);
    if (passkeyAdded) button.textContent = 'Add another';
  }
});

$('#sign-out').addEventListener('click', async () => {
  const button = $('#sign-out');
  setBusy(button, true, 'Signing out…');
  try {
    await api('/api/auth/logout', { method: 'POST', body: '{}' });
    elements.dashboardView.classList.add('hidden');
    elements.authView.classList.remove('hidden');
    showMode('login');
    $('#login-identifier').value = '';
    setMessage(elements.authMessage, 'You have signed out securely.', 'success');
  } catch (error) {
    setMessage(elements.dashboardMessage, error.message);
  } finally {
    setBusy(button, false);
  }
});

async function initialise() {
  try {
    await loadDashboard();
  } catch {
    showMode('login');
  }
}

initialise();
