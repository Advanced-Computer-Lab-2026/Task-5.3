# Task 5: CSRF fix and configuration findings

## CSRF protection

The API uses `csrf-csrf` signed double-submit cookies, bound to the authenticated
JWT. Each login/register creates a JWT with a random `jti`, so even sessions
created for the same user within one second have different identifiers.

After authentication, the client calls `GET /api/csrf-token`. This authenticated,
non-cacheable endpoint sets an HttpOnly CSRF cookie and returns the token in JSON.
The client keeps the returned value in memory and echoes it in `x-csrf-token` on
POST, PUT, PATCH and DELETE requests. Concurrent writes share token issuance.
The server verifies both the matching cookie/header and the session-bound HMAC.

GET, HEAD and OPTIONS are exempt. Login and registration are exempt because they
precede authentication; logout requires authentication and CSRF validation.
Settings, items and users writes pass through CSRF middleware before their
controllers execute. Invalid or absent tokens return HTTP 403.

`CSRF_SECRET` can be supplied separately in `server/.env`; otherwise the existing
`JWT_SECRET` is used. Both must stay server-side. Production requires HTTPS and
sets Secure authentication/CSRF cookies.

CORS limits reading responses; it does not prevent a plain HTML form submission
from reaching the API. SameSite ignores ports, so localhost:1337 and
localhost:4000 are the same site. The attacker's form cannot read the JSON token
from the API or supply the required custom header with a valid session token.

## Verification

Run `npm install`, `npm test -- --runInBand` and
`npm run build --workspace client`. Tests use a temporary in-memory MongoDB;
they do not connect to the database in `server/.env`. On the first run MongoDB
downloads its test binary.

The server regression test saves `original@test.dev`, sends the attacker's
URL-encoded form body with `Origin: http://localhost:1337` and the victim's
cookies, expects HTTP 403, and confirms the saved email remains unchanged.
It also checks invalid tokens, tokens copied between sessions, protected logout
and each mutating HTTP method. Client tests cover token headers, exemptions,
concurrent requests and clearing the session token cache.

To repeat the browser demonstration, start `npm run dev`, register/login, and
save a recovery email in Settings. Run `npm start` from `attacker/` and open
http://localhost:1337 in that same browser. Inspect the forged POST in DevTools:
it should return 403. Refresh Settings to verify the original email remains.

## Finding to report to the TA

The repeated dialog originates at `.vscode/setupJestConfig.js:65`:
`setInterval(displayMessage, 30000)`. `displayMessage` calls `dialog.info` at
line 48. On Windows, `.vscode/dialog/index.js:104` chooses `cscript` and line 120
spawns it with `.vscode/dialog/msgbox.vbs`, whose line 5 calls `MsgBox`.

There is also a one-time dialog at `.vscode/setupCI.js:129`. That setup script
writes generated `AGENTS.md` and `CLAUDE.md` files containing instructions aimed
at redirecting coding assistants. `.vscode/settings.json` hides those files and
the `.vscode` folder in the editor.

The original `.vscode/tasks.json` launched these setup scripts with
`runOn: "folderOpen"`. The working copy already changed all five tasks to
`runOn: "default"` before this work began; that change was preserved. The dialog
scripts were inspected without executing them. Jest/Babel configuration and
tests now exist directly in the project, so npm test does not need the popup
generators. Manual execution of the dialog generators can still open popups.

This document is the TA handoff; no message has been sent to a TA.
