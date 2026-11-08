// Passkey / Windows Hello demo
// Express + SimpleWebAuthn (v13). Data is kept IN MEMORY only: restart = reset.

const express = require('express');
const session = require('express-session');
const path = require('path');
const { randomBytes } = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const PORT = 3000;

// Relying Party settings. For localhost these must match what's in the browser URL bar.
const RP_NAME = 'Passkey Demo';
const RP_ID = 'localhost'; // your domain in production, e.g. "example.com"
const ORIGIN = `http://localhost:${PORT}`; // https://example.com in production

const app = express();
app.use(express.json());
app.use(
  session({
    secret: 'change-this-in-production',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: true, sameSite: 'lax' },
  })
);

// Serve the SimpleWebAuthn browser bundle straight from node_modules (no CDN needed)
app.get('/simplewebauthn-browser.js', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js')
  );
});
app.use(express.static(path.join(__dirname, 'public')));

// ---- "Database" (in memory) ----
// users: username -> { id: Uint8Array, username, credentials: [{ id, publicKey, counter, transports }] }
const users = new Map();

const getUser = (username) => users.get(username);

// ---- Registration ----
app.post('/api/register/options', async (req, res) => {
  const username = String(req.body.username || '').trim();
  if (!username) return res.status(400).json({ error: 'Username is required' });

  let user = getUser(username);
  if (!user) {
    user = {
      id: new Uint8Array(randomBytes(16)),
      username,
      credentials: [],
    };
    users.set(username, user);
  }

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: user.id,
    userName: user.username,
    attestationType: 'none',
    // Don't let the same authenticator register twice for this user
    excludeCredentials: user.credentials.map((c) => ({
      id: c.id,
      transports: c.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required', // forces PIN / fingerprint / face
    },
  });

  req.session.registerChallenge = options.challenge;
  req.session.registerUsername = username;
  res.json(options);
});

app.post('/api/register/verify', async (req, res) => {
  const username = req.session.registerUsername;
  const expectedChallenge = req.session.registerChallenge;
  const user = username && getUser(username);
  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'No registration in progress' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });

    if (!verification.verified) {
      return res.status(400).json({ verified: false, error: 'Verification failed' });
    }

    const { credential } = verification.registrationInfo;
    user.credentials.push({
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports,
    });

    req.session.registerChallenge = null;
    res.json({ verified: true });
  } catch (err) {
    console.error(err);
    res.status(400).json({ verified: false, error: err.message });
  }
});

// ---- Authentication ----
app.post('/api/login/options', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const user = username && getUser(username);
  if (!user || user.credentials.length === 0) {
    return res.status(404).json({ error: 'No passkey registered for that username' });
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: user.credentials.map((c) => ({
      id: c.id,
      transports: c.transports,
    })),
  });

  req.session.loginChallenge = options.challenge;
  req.session.loginUsername = username;
  res.json(options);
});

app.post('/api/login/verify', async (req, res) => {
  const username = req.session.loginUsername;
  const expectedChallenge = req.session.loginChallenge;
  const user = username && getUser(username);
  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'No login in progress' });
  }

  const credential = user.credentials.find((c) => c.id === req.body.id);
  if (!credential) {
    return res.status(400).json({ error: 'Unknown credential' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential,
      requireUserVerification: true,
    });

    if (!verification.verified) {
      return res.status(401).json({ verified: false, error: 'Verification failed' });
    }

    // Update the signature counter (helps detect cloned authenticators)
    credential.counter = verification.authenticationInfo.newCounter;

    req.session.loginChallenge = null;
    req.session.user = username; // user is now "logged in"
    res.json({ verified: true, username });
  } catch (err) {
    console.error(err);
    res.status(400).json({ verified: false, error: err.message });
  }
});

// ---- Session ----
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Example of a protected route
app.get('/api/secret', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json({ secret: `Hello ${req.session.user}, this data is only for verified users.` });
});

app.listen(PORT, () => {
  console.log(`Passkey demo running at ${ORIGIN}`);
  console.log('Open it using "localhost" (not 127.0.0.1) so the RP ID matches.');
});
