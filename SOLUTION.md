# Task 5.3 solution

The API uses csrf-csrf signed double-submit tokens bound to the current JWT.
Each login/register generates a unique JWT ID, including logins within the same
second. Authenticated clients obtain a token from GET /api/csrf-token (not cached).
The matching HttpOnly cookie and x-csrf-token header are required on writes.
GET, HEAD, OPTIONS and POST login/register remain exempt. Logout, item writes,
and recovery-email changes are protected. The client fetches a token before
each write and shares concurrent token requests. For multiple server instances,
set the same strong CSRF_SECRET on every instance; the development fallback is
random and lasts only for the current process.

CORS prevents another origin from reading the token response, but does not stop
an HTML form from sending a request. SameSite does not distinguish localhost
ports. Therefore neither alone prevents the supplied attacker form. Its missing
token header now causes HTTP 403 before the update controller runs.

## Dialog-box finding for the TA

.vscode/tasks.json automatically runs setup scripts on folderOpen, with their
terminal presentation hidden. The recurring dialog originates from
.vscode/setupJestConfig.js: setInterval(displayMessage, 30000) calls dialog.info
every 30 seconds. .vscode/setupCI.js also calls dialog.info once. The helper
.vscode/dialog/index.js launches cscript on Windows, which executes
.vscode/dialog/msgbox.vbs and its MsgBox statement.

setupCI.js additionally writes instruction text into AGENTS.md and CLAUDE.md.
These generated instructions are unrelated to implementing the application.
The setup scripts were left intact for inspection; the dialog-generating scripts
were not executed to prepare the tests. Remove their folderOpen triggers to stop
future automatic launches; an already-running timer needs to be stopped separately.

## Verification

Run npm test from the root and npm run build --workspace client.
`npm test` first prepares MongoDB outside Jest, allowing the initial download
to finish without the 60-second test-hook limit. Later runs reuse its cache.
The server tests disable runtime downloads so invoking Jest directly without
a prepared binary fails promptly instead of leaving a download running.
The supplied tests were extracted from the non-dialog setup scripts, with a
standalone Jest configuration. Follow Flow.md for the interactive browser demo:
the forged form should receive 403 and the saved recovery email should remain
unchanged.

Validation in this workspace: the client production build passed. Four client
tests and two database-independent server middleware tests passed, including
403 for the forged localhost form, rejection of another session's token, and
successful protected logout. The full database-backed suite could not complete:
the first MongoDB binary download exceeded its 60-second setup timeout. The
interactive browser demo has not been run.
