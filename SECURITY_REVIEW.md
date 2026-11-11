# Task 5.3 review

## CSRF protection

The API uses `csrf-csrf` to issue a signed double-submit token through the
authenticated `GET /api/csrf-token` endpoint. Authenticated writes require the
matching cookie and `x-csrf-token` header. Login and registration remain exempt,
and the client sends them without requesting an authenticated token first.

The CSRF signature is bound to the authentication cookie. Each login creates a
JWT with a random `jti`, so two logins for the same user have distinct sessions.
A token from a previous session fails validation; fetching a fresh token replaces
the stale CSRF cookie. The development fallback CSRF secret is randomly generated
at process startup. Set a shared `CSRF_SECRET` when running multiple API instances.

CORS alone does not stop an HTML form submission from changing server state.
Different localhost ports are different origins but the same site, so the
`SameSite=Lax` session cookie is still sent in this demonstration. The token
header supplies the additional proof required for authenticated writes.

## Popup source to report to the TA

The original `.vscode/tasks.json` ran setup scripts automatically with
`runOptions.runOn: "folderOpen"` and hid their terminal output.
`.vscode/setupJestConfig.js` called `setInterval(displayMessage, 30000)`;
`displayMessage` used `dialog.info` from `.vscode/dialog/index.js` to display
the recurring native popup. `.vscode/setupCI.js` also displayed a one-time
dialog. The helper launches platform-specific native dialog programs.

The current changes remove both scripts' dialog calls and remove automatic
folder-open execution from the setup tasks. The helper files remain on disk.
These findings identify the popup mechanism; they do not establish that data
was stolen or that a backdoor was installed.

## Verification

- `npm test -- --runInBand`: two suites, eight tests passed.
- Coverage includes pre-auth client requests, legitimate recovery-email updates,
  missing tokens, rejection of a previous session's token, and recovery after
  fetching a fresh token.
- An automated form-encoded request with origin `http://localhost:1337`, using
  the logged-in victim's cookies but no token header, receives `403`. A subsequent
  read confirms that the saved recovery email is unchanged.
- `npm run build --workspace client`: passed.

The temporary test database is pinned to MongoDB 7.0.14 because the default 8.2.6
binary crashes on this Mac with a missing libc++ symbol. This setting affects
the test database only.

The automated form test reproduces the attack's HTTP request. The interactive
browser walkthrough in `Flow.md` has not been performed during this review.
