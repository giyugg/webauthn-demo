const { startRegistration, startAuthentication, browserSupportsWebAuthn } = SimpleWebAuthnBrowser;

const $ = (id) => document.getElementById(id);
const statusEl = $('status');

function setStatus(msg, type = '') {
  statusEl.textContent = msg;
  statusEl.className = type;
}

async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function showDashboard(username) {
  $('who').textContent = username;
  $('auth').style.display = 'none';
  $('dashboard').style.display = 'block';
}

function showAuth() {
  $('dashboard').style.display = 'none';
  $('auth').style.display = 'block';
  $('secretOut').textContent = '(protected data will show here)';
}

// ---- Register a new passkey ----
$('registerBtn').addEventListener('click', async () => {
  const username = $('username').value.trim();
  if (!username) return setStatus('Enter a username first.', 'err');

  try {
    setStatus('Waiting for Windows Security...');
    const options = await post('/api/register/options', { username });

    // This call is what makes Windows show the "Making sure it's you" prompt
    const attResp = await startRegistration({ optionsJSON: options });

    const result = await post('/api/register/verify', attResp);
    if (result.verified) setStatus('Passkey created! Now click "Sign in".', 'ok');
  } catch (err) {
    if (err.name === 'InvalidStateError') {
      setStatus('A passkey for this account already exists on this device.', 'err');
    } else if (err.name === 'NotAllowedError') {
      setStatus('Cancelled or timed out.', 'err');
    } else {
      setStatus(err.message, 'err');
    }
  }
});

// ---- Sign in with a passkey ----
$('loginBtn').addEventListener('click', async () => {
  const username = $('username').value.trim();
  if (!username) return setStatus('Enter a username first.', 'err');

  try {
    setStatus('Waiting for Windows Security...');
    const options = await post('/api/login/options', { username });

    const asseResp = await startAuthentication({ optionsJSON: options });

    const result = await post('/api/login/verify', asseResp);
    if (result.verified) {
      setStatus('');
      showDashboard(result.username);
    }
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      setStatus('Cancelled or timed out.', 'err');
    } else {
      setStatus(err.message, 'err');
    }
  }
});

// ---- Protected API + logout ----
$('secretBtn').addEventListener('click', async () => {
  try {
    const res = await fetch('/api/secret');
    const data = await res.json();
    $('secretOut').textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    $('secretOut').textContent = err.message;
  }
});

$('logoutBtn').addEventListener('click', async () => {
  await post('/api/logout');
  showAuth();
  setStatus('Logged out.');
});

// ---- On load ----
(async () => {
  if (!browserSupportsWebAuthn()) {
    setStatus('This browser does not support WebAuthn.', 'err');
    $('registerBtn').disabled = true;
    $('loginBtn').disabled = true;
    return;
  }
  const me = await fetch('/api/me').then((r) => r.json());
  if (me.user) showDashboard(me.user);
})();
