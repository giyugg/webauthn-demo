# Passkey / Windows Hello Demo

A small full-JavaScript demo of WebAuthn passkeys: Express on the server, plain HTML/JS in the browser, using the SimpleWebAuthn library.

When you click **Create passkey** or **Sign in**, the browser asks Windows to verify you, and Windows shows its own "Making sure it's you" dialog (PIN, fingerprint, or face). The server then verifies the cryptographic signature, so the check is real and not just a UI prompt.

## Run it

Requires Node.js 18 or newer.

```bash
npm install
npm start
```

Then open **http://localhost:3000** (use `localhost`, not `127.0.0.1`).

1. Type a username.
2. Click **Create passkey** and approve the Windows prompt.
3. Click **Sign in** and approve it again.

## Files

| File | What it does |
| --- | --- |
| `server.js` | Express API: generates challenges, verifies registration and login, keeps the session |
| `public/index.html` | The page |
| `public/app.js` | Calls the browser WebAuthn API through SimpleWebAuthn and talks to the server |

## How the flow works

**Register:** the browser asks the server for options and a random challenge. The browser passes them to Windows Hello, which creates a key pair. The private key never leaves the device. The browser sends the public key back, and the server verifies and stores it.

**Sign in:** the server sends a new random challenge. Windows Hello asks for your PIN/biometric and signs the challenge. The server checks the signature against the stored public key.

## Notes

- WebAuthn only works on **HTTPS**, except on `localhost`.
- Users and passkeys are stored **in memory**, so restarting the server clears them. Swap the `users` Map in `server.js` for a real database to keep them.
- To deploy, change `RP_ID` (your domain) and `ORIGIN` (`https://your-domain`) in `server.js`, serve over HTTPS, and set a real session secret.
- The Windows dialog's look and wording are controlled by the OS and can't be customized.
