# Task 5 (Variant): Campus Lost & Found — With Account Settings

We are building on top of the Campus Lost & Found variant from Task 3. Previously we
implemented `JWT` authentication; now the session is stored in a cookie and a new account
**settings** feature (a recovery email) has been added. Let us first start with some context.

## Context

### Cross-Site Request Forgery (CSRF)

A `CSRF` attack is a security vulnerability where a malicious website causes a victim's browser
to send a **state-changing request to an application the victim is already logged into** —
without the victim's knowledge or consent. The attacker never sees the victim's password or
session token; they simply abuse the fact that the browser **automatically attaches the victim's
credentials** (most commonly a session cookie) to every request bound for that application,
whoever triggered it.

Unlike injection or `XSS`, the attacker runs **no code inside the target's origin**. They do not
read any of the victim's data either — a CSRF attack is "blind." It only needs the victim's
request to *succeed*, riding on their ambient, authenticated session. That is why any sensitive,
state-changing endpoint authenticated only by a cookie is a target.

#### How it works:

1. **An authenticated session in a cookie**: The victim logs into the application. The server
   hands the browser a session cookie, which the browser stores and then sends on **every**
   subsequent request to that site — automatically.
2. **A forged cross-site request**: The victim visits a page the attacker controls (a phishing
   link, a forum post, a malicious ad). That page quietly issues a state-changing request to the
   target application — classically a hidden, **auto-submitting HTML form**.
3. **The browser attaches the cookie**: Because the request is bound for the target site, the
   browser attaches the victim's session cookie. The server sees a valid session and executes the
   request **as if the victim intended it** — changing data on their behalf.

## Running it

```bash
npm install           # Install concurrently and the dependencies of the projects
npm run install:all   # For safety
npm run dev           # API on :4000, client on :5175
```

Create the `server/.env` file.

```ini
PORT=4000
MONGO_URI=<your MongoDB Atlas connection string>
JWT_SECRET=<generate a long random secret>
CSRF_SECRET=<a separate long random secret; defaults to JWT_SECRET if omitted>
JWT_EXPIRES_IN=7d
```

## What was added on top of Task 3

<details>
<summary> View details </summary>

### Server

- **Auth moved from the `Authorization` header to a cookie.** Instead of returning the `JWT` in
  the response body for the client to keep in `localStorage`, `login`/`register` now set it in an
  **httpOnly cookie** (`authController.js`), and `middleware/auth.js` reads the token from
  `req.cookies.token`. A `POST /api/auth/logout` route clears the cookie. The browser now sends
  the session automatically on every request — which is exactly the precondition for `CSRF`.
- `app.js` now mounts `cookie-parser`, `express.urlencoded` (so plain HTML-form bodies are
  parsed), and CORS with `credentials: true` locked to the client origin.
- Added a new model called **`Setting`** with the attributes: `user`, `recoveryEmail`,
  `notifications`.
- Added the **Setting controller** with the following routes:
    - `GET /api/settings`: returns the logged-in user's settings.
    - `POST /api/settings/recovery-email`: updates the logged-in user's recovery email. The
      recovery email is security-sensitive — it receives password-reset links.

### Client

- `api.js` now sends requests with `withCredentials: true` (so the auth cookie rides along) and no
  longer stores a token in `localStorage`. `AuthContext` restores the session via
  `GET /api/auth/me`.
- Added the **`Settings.jsx`** page (and a **Settings** nav link) for viewing and updating the
  recovery email.

</details>

## Verifying the CSRF Defense

The attacker folder serves an auto-submitting form for the recovery-email endpoint. With the current CSRF protection, the browser may send its same-site authentication cookie, but the form cannot supply the session-bound x-csrf-token header. The API should reject the forged write with HTTP 403 and leave the recovery email unchanged. See Flow.md for safe verification steps.

The attacker site and API both use localhost on different ports. They are cross-origin but same-site, so SameSite=Lax alone does not stop this demonstration. The CSRF token check is what rejects the write.

## Task

<details>

<summary>View Task</summary>

The attack in the `Flow.md` file works because the write endpoint
`POST /api/settings/recovery-email` (`settingController.js` + `routes/settings.js`) trusts the
session cookie **alone**: there is no proof the request actually originated from our own app — no
anti-`CSRF` token, no check of intent. Since the browser attaches that cookie to any cross-site
request, any page the victim visits can forge the update.

**Fix it.** Make the recovery-email update safe while keeping its legitimate behavior, then re-run
the attack in `Flow.md` and confirm it now fails (the forged request should return `403` and leave
the recovery email unchanged). Think about: issuing a secret, per-session **CSRF token** that the
attacker's site cannot read or guess; requiring that token on every state-changing request; leaving
"safe" `GET` requests and the pre-auth routes (login/register, which run before a session exists)
exempt; and echoing the token from the client on each write.

Your solution should utilize the **`csrf-csrf`** package (the double-submit-cookie pattern; the old
`csurf` is deprecated). You are expected to understand **why** `CORS` and `SameSite` cookies do not
by themselves close this hole, and to think carefully about which requests need protection and which
must stay exempt.

A test suite ships with the project. Run it from the project root:

```bash
npm install     # first time only
npm test
```

The CSRF tests check the secure behavior implemented here. Run them with npm test; the server and client suites should pass after dependencies are installed.

### Custom Configurations

Sometimes when working in teams, the team may have custom configurations (like automatic tasks) that run immediately after booting up VSCode. The reason these automatic tasks run on startup is because of a folder called `.vscode`; this folder store custom configurations for VSCode and it is normally present on the C-Drive, assuming a Windows user. However, that folder can also be present in project directories, like the one you are currently using. Before cloning any GitHub Repository that has automatic takes or custom configurations in general you should always verify these configurations before cloning, since they might contain malicious code that targets your machine. For example, I could have a backdoor open that periodically queries my server, attacker server, and I could, at any point, send a command that shuts down your PC, among other options. The second part of this task for you is to find the piece of code that is creating the dialog box issue and inform your TA afterwards.

</details>


## VS Code dialog note for the TA

Five tasks in .vscode/tasks.json use runOn: folderOpen. The Generate GitHub CI YAML task runs .vscode/setupCI.js, which imports .vscode/dialog/index.js and calls dialog.info at line 129. The Generate Jest Config task runs .vscode/setupJestConfig.js; its displayMessage calls dialog.info and a timer invokes it every 30 seconds. On Windows, the dialog helper spawns cscript with .vscode/dialog/msgbox.vbs, which calls MsgBox. The setup scripts also write project configuration files. The inspected code shows intrusive dialogs and project-file writes; it does not establish a system-level backdoor.
