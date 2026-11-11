# CSRF protection and VS Code startup fixes

The API uses `csrf-csrf` 4's signed double-submit-cookie pattern. After
authentication, `GET /api/csrf-token` returns a token and sets an HttpOnly cookie.
The token is signed with `CSRF_SECRET` and bound to the authenticated JWT. Each
login has a random `jti`, so a previous login's token cannot authorize a new one.
If `CSRF_SECRET` is unset, a random process-local secret is used; configure a
shared, strong secret for deployments with multiple API processes.

Every existing authenticated write requires the cookie and matching
`x-csrf-token` header: recovery-email updates, item create/edit/delete, user
edit/delete, and logout. Authentication runs before CSRF validation. Safe reads
and pre-authentication login/register remain exempt. Invalid CSRF requests return
403 with `code: EBADCSRFTOKEN` before any controller modifies data.

The Axios interceptor fetches the current session's token before each write,
sharing issuance among concurrent writes. It does not persist tokens across
logins. Token issuance responses are not cacheable. Login/register and logout
clear the CSRF cookie. Production cookies use Secure; the production CSRF cookie
also uses the `__Host-` prefix. Serve production over HTTPS.

CORS restricts browser access to responses but does not prevent ordinary HTML
forms from being sent. SameSite cookies do not stop this demo because the
localhost ports are different origins within the same site.

## Dialog issue to report to the TA

The original `.vscode/tasks.json` ran setup scripts on `folderOpen`, with terminal
output hidden. `.vscode/setupCI.js` displayed a startup dialog and generated
`AGENTS.md` and `CLAUDE.md` containing instructions intended to redirect assistants.
`.vscode/setupJestConfig.js` called `setInterval(displayMessage, 30000)`, displaying
another dialog every 30 seconds. The helper `.vscode/dialog/index.js` spawned
`cscript` on Windows to run `.vscode/dialog/msgbox.vbs`, whose `MsgBox` call
created the actual popup. `.vscode/settings.json` hid these files in Explorer.

The automatic tasks have been replaced with a manual test task; automatic tasks
are disabled in workspace settings. Files are no longer hidden. The CI setup
script now only creates CI configuration when explicitly invoked, and the Jest
setup script has no side effects. Tests and configuration are checked in and do
not depend on VS Code startup. Existing running tasks from before this change
can be stopped using VS Code's **Tasks: Terminate Task** command.

## Verification

Verified: both Jest suites pass (27 tests) using the assignment MongoDB server
with an isolated test database and record cleanup. The client production build
also passes. The first in-memory run timed out downloading the 781 MB Windows
MongoDB archive, so external test mode was used for the integration checks.

Run `npm install`, `npm test -- --runInBand`, and
`npm run build --workspace client`. In PowerShell environments that disable
`npm.ps1`, use `npm.cmd` instead of `npm`.

The server suite normally downloads an in-memory MongoDB binary on its first
run. To use an available MongoDB server instead, explicitly set `TEST_MONGO_URI`.
That mode creates a uniquely named `csrf_test_*` database and deletes the test
records after the run; it does not use the application's database name. Empty
test collections may remain because assignment credentials can prohibit dropping
databases.

The tests include the attacker form's URL-encoded POST with
`Origin: http://localhost:1337`, requiring 403 and an unchanged recovery email.
They also cover legitimate updates, tampering, missing tokens, cross-session
tokens, other write routes, logout, and client token handling.

For browser verification, follow `Flow.md` to log in, save a recovery email, and
visit `http://localhost:1337`. The hidden form should receive 403; refresh Settings
to confirm the original value remains. The manual browser walkthrough has not
been run; the automated HTTP regression reproduces its forged form submission.
