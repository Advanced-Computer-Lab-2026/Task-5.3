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
http://localhost:4000/api/settings` in a logged-in tab). The recovery email is now
**`attacker@evil.com`** — changed without your consent. From here the attacker triggers a
password reset and receives the link. **Account takeover.**

> Want to watch it happen? Open DevTools → **Network** on the attacker page before it loads,
> and you will see the cross-site `POST` to `/api/settings/recovery-email` return `200`, with
> your `token` cookie attached under **Request Headers → Cookie**.

---

## 4. Why it works (the vulnerable code path)

1. **Auth is a cookie the browser sends for you** — `server/src/middleware/auth.js` reads the
   JWT from `req.cookies.token`. The victim's browser attaches it to the attacker's forged
   request automatically; the server cannot tell the difference between that and a real click.
2. **The write trusts the cookie alone** — `server/src/controllers/settingController.js`
   (`updateRecoveryEmail`) performs the update with **no proof the request came from our own
   app**: no anti-CSRF token, no check that a real user action triggered it.
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

The fix: require a secret, per-session **CSRF token** on every state-changing request — a value
the attacker's site cannot read or guess. The solution project does this with the `csrf-csrf`
package.

---

## 5. Running the tests locally

A test suite ships with the project. Run it from the **project root**:

```bash
npm install     # first time only
npm test
```

What to expect **in this vulnerable project**:

- The tests describe the **secure** behavior the feature *should* have: a forged request with no
  CSRF token is rejected (server), and the client attaches a CSRF token to mutating requests.
- So here they are **expected to FAIL** (the suite is red). That red result is the starting
  point — your job is to make them green by adding CSRF protection. The solution project shows
  them all passing.

Notes:

- The server tests spin up an **in-memory MongoDB** via `mongodb-memory-server`. The first run
  downloads a small `mongod` binary, so you need **internet access the first time** (cached after).
- You need **Node.js 18+ (20 recommended)**.
- The same `npm test` works on **Windows, macOS, and Linux**.
