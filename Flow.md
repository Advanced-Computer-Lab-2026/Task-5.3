# Flow — Simulating the CSRF Attack

This project includes a recovery-email feature and a local attacker page for demonstrating
Cross-Site Request Forgery (CSRF). The API now rejects the attack; use these steps to verify
that the forged update returns `403` and does not change the saved recovery email.

The app authenticates every request with a **JWT stored in an httpOnly cookie**. Because the
browser attaches that cookie **automatically** to *every* request to the API — including
requests triggered by a completely different website — an attacker's page can forge a
state-changing request **in the victim's name** without ever seeing their password or token.
That is a **Cross-Site Request Forgery (CSRF)** bug.

Follow the steps to simulate the forged request, then read why the original attack worked and
how the fix blocks it.

---

## 0. Prerequisites & setup

From the **project root** (`Task-5.3/`):

```bash
npm install          # installs server + client (npm workspaces) + test tooling
```

Create `server/.env` if needed, or add the CSRF secret to the existing file:

```
PORT=4000
MONGO_URI=<your MongoDB connection string>
JWT_SECRET=<any long random string>
JWT_EXPIRES_IN=7d
CSRF_SECRET=<a different long random string>
```

Start the app:

```bash
npm run dev          # API on http://localhost:4000, client on http://localhost:5175
```

Open the client at **http://localhost:5175**.

---

## 1. Become the victim

1. Click **Register** and create a user (e.g. `victim@test.dev` / `secret123`).
2. You are now logged in. Open DevTools → **Application → Cookies → http://localhost:4000**
   and note the `token` cookie. It is **HttpOnly** (JavaScript cannot read it) — but the
   browser still sends it on every request to the API.
3. Click **Settings**. Set your recovery email to something you recognise, e.g.
   `victim@test.dev`, and save. This is the value the attacker is about to overwrite.

**Leave this browser logged in.** A CSRF attack only works against an authenticated victim.

---

## 2. Run the attacker site

The `attacker/` folder is a tiny, separate Express server that plays the role of "some random
site the victim visits" (a phishing link, a forum post, an ad iframe…).

In a **second terminal**:

```bash
cd attacker
npm install
npm start            # Attacker site on http://localhost:1337
```

---

## 3. Spring the trap

In the **same browser** where you are logged in as the victim, open:

```
http://localhost:1337
```

It looks like a harmless "You won a prize!" page. But on load it **auto-submits a hidden
form** that POSTs to `http://localhost:4000/api/settings/recovery-email` with
`recoveryEmail=attacker@evil.com`, targeting a hidden iframe so you see nothing.

Now check the request in DevTools → **Network**. The forged `POST` to
`http://localhost:4000/api/settings/recovery-email` should return **`403 Forbidden`**. Go back
to the app tab and refresh the Settings page (or `GET http://localhost:4000/api/settings` in a
logged-in tab): the recovery email should remain the value you set. The attacker's form cannot
provide the CSRF header required by the API.

> The browser may still attach the auth cookie (and same-site CSRF cookie) to the form request.
> That is expected: the server rejects it because the attacker cannot supply a valid
> `x-csrf-token` header.

---

## 4. Why the old attack worked, and why it now fails

1. **Cookies authenticate automatically.** `server/src/middleware/auth.js` reads the JWT from
   `req.cookies.token`; the browser can attach it to a cross-origin request without the attacker
   ever reading it.
2. **CORS alone is not CSRF protection.** CORS controls whether an origin may read a response; a
   simple HTML form can still send a request, and the server could still act on it.
   `SameSite=Lax` also does not stop this local demonstration: `localhost:1337` and
   `localhost:4000` are different origins but the same site, because ports do not define a site.
3. **Writes now require a session-bound token.** The app's `csrf-csrf` middleware validates every
   non-safe request, except `POST /api/auth/login` and `POST /api/auth/register`, which are
   pre-authentication routes. Safe `GET`, `HEAD`, and `OPTIONS` requests remain exempt. The
   authenticated `GET /api/csrf-token` issues a signed double-submit token whose HMAC is tied to
   the JWT session and the server-only `CSRF_SECRET`.
4. **The legitimate client echoes the token.** `client/src/api.js` fetches the token before each
   write and sends it in the `x-csrf-token` header. The CSRF cookie is HttpOnly, and the
   attacker-origin page cannot read the token response due to the CORS origin restriction.
   A plain form cannot add the required header, so the middleware returns `403` before any
   controller can update data.

`SameSite` remains useful defense-in-depth, but it does not replace a CSRF token. CORS and token
validation work together: CORS prevents the attacker origin from retrieving the token, and the
server verifies the token on writes.

---

## 5. Running the tests locally

A test suite ships with the project. Run it from the **project root**:

```bash
npm install     # first time only
npm test
```

What to expect after the fix:

- A logged-in update with a valid token succeeds, while a forged update without the token returns
  `403` and leaves the recovery email unchanged.
- The client attaches the token to writes; safe reads and pre-authentication registration/login
  remain usable.
- The tests should pass.

Notes:

- The server tests use in-memory user/settings model stubs and do not require MongoDB or download
  a database binary.
- You need **Node.js 18+ (20 recommended)**.
- The same `npm test` works on **Windows, macOS, and Linux**.
- Keep `CSRF_SECRET` private and stable across server restarts; use a different random value from
  `JWT_SECRET`. In production, serve the app over HTTPS so the CSRF cookie's `Secure` attribute
  is enabled.
