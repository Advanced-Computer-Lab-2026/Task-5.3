# Solution — Task 5.3 (CSRF + Custom Configurations)

## Part 1 — CSRF fix (`csrf-csrf`, double-submit cookie)

| File | Change |
|---|---|
| `server/src/middleware/csrf.js` (new) | `doubleCsrf(...)` config: secret from `CSRF_SECRET`, token bound to the session (`req.cookies.token`), token read from the `x-csrf-token` header, `GET/HEAD/OPTIONS` ignored. |
| `server/src/app.js` | New `GET /api/csrf-token` that issues a token. `/api/auth` (login/register/logout) is mounted **before** the protection (no session exists yet). `doubleCsrfProtection` guards every route after it (items, users, settings). |
| `client/src/api.js` | Axios interceptor: on every mutating request, fetch the token once and send it as `x-csrf-token`. Token is reset after login/logout, and a `403` refreshes it and retries once. |
| `server/package.json` | Added `csrf-csrf`. |

**Why it works:** the attacker's auto-submitting `<form>` still carries the victim's cookies, but it
cannot read the token (CORS blocks reading `/api/csrf-token` cross-origin) and a plain HTML form cannot
set a custom header — so the request has no `x-csrf-token` and is rejected with **403**.

**Why CORS / SameSite are not enough:** CORS only stops the attacker *reading* the response — the
browser still *sends* the request and the server still acts on it. `SameSite=Lax` keys off the
registrable domain, not the port, so `localhost:1337` → `localhost:4000` counts as same-site and the
cookie is still sent.

### Demo (two tabs in Chrome)
1. `npm run dev` (root) and `cd attacker && npm start`.
2. Tab 1 — `http://localhost:5175`: register, open **Settings**, save `victim@test.dev` → "Recovery email updated." (legit flow still works).
3. Tab 2 — `http://localhost:1337` (the "You won a prize" page). DevTools → Network shows the forged `POST /api/settings/recovery-email` → **403**.
4. Back to Tab 1, refresh **Settings** → still `victim@test.dev` (not `attacker@evil.com`).

## Part 2 — The dialog-box issue (`.vscode`)

`.vscode/tasks.json` defines 5 tasks with `"runOn": "folderOpen"` and `"reveal": "never"`, so they run
silently every time the folder is opened in VS Code.

- **`.vscode/setupJestConfig.js`** — the culprit for the repeating popups: last line
  `setInterval(displayMessage, 30000);` shows a random dialog **every 30 seconds** forever.
- **`.vscode/setupCI.js`** — shows the one-off "Seriously???" dialog (`await dialog.info(...)`), and also
  writes `.github/workflows/ci.yaml`, `CLAUDE.md` and `AGENTS.md` (the last two are git-ignored).
- **`.vscode/dialog/index.js` + `msgbox.vbs`** — the code that actually spawns the box
  (`cscript msgbox.vbs` on Windows, `zenity` on Linux, `osascript` on macOS).
- **`.vscode/settings.json`** hides `.vscode`, `CLAUDE.md` and `AGENTS.md` from the explorer
  (`files.exclude`) so all of this is easy to miss.

Lesson: review `.vscode/tasks.json` (especially `runOn: folderOpen`) before opening a cloned repo, or
open it in VS Code's Restricted Mode.
