# Flow — Simulating the CSRF Attack

This project ships a **deliberately vulnerable** feature: the **account recovery email**
(`/settings`). Changing it is a sensitive, state-changing action — whoever controls your
recovery email can request password-reset links and take over your account.

The app authenticates every request with a **JWT stored in an httpOnly cookie**. Because the
browser attaches that cookie **automatically** to *every* request to the API — including
requests triggered by a completely different website — an attacker's page can forge a
state-changing request **in the victim's name** without ever seeing their password or token.
That is a **Cross-Site Request Forgery (CSRF)** bug.

Follow the steps to reproduce it, then read *Why it works*, then run the tests.

---

## 0. Prerequisites & setup

From the **project root** (`Task-5.3/`):

```bash
npm install          # installs server + client (npm workspaces) + test tooling
```

Create `server/.env` (if missing):

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

Now go back to the app tab and **refresh the Settings page** (or `GET
http://localhost:4000/api/settings` in a logged-in tab). With the CSRF fix applied, the forged
request is rejected with **`403 Forbidden`**, and your recovery email remains unchanged.

> Want to watch it happen? Open DevTools → **Network** on the attacker page before it loads,
> and you will see the cross-site `POST` to `/api/settings/recovery-email` return `403`, with
> your `token` cookie attached under **Request Headers → Cookie**. The attacker cannot read
> the CSRF token or set the required `x-csrf-token` header.

---

## 4. Why it works (the vulnerable code path)

1. **Auth is a cookie the browser sends for you** — `server/src/middleware/auth.js` reads the
   JWT from `req.cookies.token`. The victim's browser still attaches it to the attacker's forged
   request automatically.
2. **The write now also requires a CSRF token** — the `csrf-csrf` middleware checks a signed
   token bound to the session JWT. The client obtains it from `GET /api/csrf-token` and sends it
   in the `x-csrf-token` header on every state-changing request.
3. **The body is a plain form** — `server/src/app.js` parses `urlencoded` bodies, so a bare
   HTML `<form>` POST (which needs no JavaScript and triggers no CORS preflight) is enough.
4. **CORS does not save you.** CORS only blocks the attacker from *reading* the response; the
   browser still *sends* the request and the server still *acts on it*. CSRF is about the
   write succeeding, not about reading the reply.

> ### Why `SameSite` doesn't save you here
> The auth cookie is `SameSite=Lax`. You might expect that to block a cross-site POST — and
> across true different sites (`evil.com` → `yourbank.com`) it largely would. But the attacker
> page (`localhost:1337`) and the API (`localhost:4000`) are the **same site**: the port is not
> part of a site's identity, only the registrable domain is. So the cookie is sent. This is a
> deliberate lesson: **`SameSite` is a useful layer but not a substitute for a real anti-CSRF
> token.** The fix the solution uses works regardless of site/port.

The middleware leaves safe `GET`, `HEAD`, and `OPTIONS` requests and pre-authentication
`POST /api/auth/login` and `POST /api/auth/register` exempt. Other state-changing requests made
with an authenticated session require a valid token.

---

## 5. Running the tests locally

A test suite ships with the project. Run it from the **project root**:

```bash
npm install     # first time only
npm test
```

What to expect after applying the fix:

- The tests verify that a legitimate update succeeds when accompanied by a CSRF token, a forged
  request without one returns `403` without changing the recovery email, and the client attaches
  the token to writes.
- All CSRF tests should pass.

Notes:

- The server tests spin up an **in-memory MongoDB** via `mongodb-memory-server`. The first run
  downloads a small `mongod` binary, so you need **internet access the first time** (cached after).
- You need **Node.js 18+ (20 recommended)**.
- The same `npm test` works on **Windows, macOS, and Linux**.
