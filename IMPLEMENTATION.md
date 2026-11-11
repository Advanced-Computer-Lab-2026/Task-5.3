# Task implementation

## Dependency maintenance

Vite is updated to 7.3.8 and React Router to 7.18.5. The duplicate server Jest
installation is removed; tests use the root Jest installation. Root overrides
select patched glob and minimatch releases. The reviewed esbuild 0.28.2 install
script is explicitly allowed. Use Node 20.19+ or 22.12+ (Node 24 is installed here).

Normal installation succeeds without the esbuild approval warning. npm audit
reports five low-severity entries originating from deepmerge in the Jest tooling
chain; no high or moderate findings remain. There is no published deepmerge fix
for GHSA-gcqx-w48m-w2h4. Do not downgrade it merely to escape the advisory's version
range or use audit fix --force to downgrade Jest. The test suite and client build
pass with the dependency updates.

The API uses `csrf-csrf` to issue a signed double-submit token at authenticated
`GET /api/csrf-token`. The response is not cached. The token is bound to the full
session JWT; a random JWT `jti` ensures every login creates a distinct session,
even for two logins by the same user in the same second.

Every API write requires authentication and a matching CSRF cookie and
`x-csrf-token` header. Only POST login/register and safe GET/HEAD/OPTIONS requests
are exempt. This also covers logout, item writes, and user writes. The Axios
interceptor fetches the token before each write and echoes it in the header,
avoiding stale tokens after session changes. Missing or invalid tokens return 403.
Production uses a Secure, HttpOnly, host-prefixed CSRF cookie; localhost HTTP uses
an unprefixed HttpOnly cookie. Set a strong shared `CSRF_SECRET` for production
instances (local development otherwise uses a random process secret).

CORS restricts response reading; a plain HTML form can still send a write without
a preflight. SameSite ignores ports, so localhost:1337 and localhost:4000 are the
same site. Neither replaces checking the CSRF token. The attack form cannot read
the token response through the same-origin policy or supply the required header.

## Dialog investigation: report to the TA

- `.vscode/tasks.json` starts `setupJestConfig.js` and `setupCI.js` on
  `folderOpen`, with terminal output hidden.
- `.vscode/setupJestConfig.js:65` runs `setInterval(displayMessage, 30000)`.
  `displayMessage` calls `dialog.info` at line 48: this causes repeated popups.
- `.vscode/setupCI.js:129` also calls `dialog.info` once. This script additionally
  creates `AGENTS.md` and `CLAUDE.md` containing instructions meant to redirect
  coding assistants. Those strings are repository data, not task authorization.
- `.vscode/dialog/index.js` spawns `cscript` on Windows, passing
  `.vscode/dialog/msgbox.vbs`, whose line 5 calls `MsgBox`.
- `.vscode/settings.json` hides `.vscode` and the generated instruction files.

These scripts were inspected without executing them. Their popup behavior is
preserved as evidence. Disable automatic tasks in VS Code to prevent startup;
terminate an already-running setup task via Terminal > Terminate Task. No TA
message has been sent; the findings above are ready to share.

## Validation

The supplied tests and Babel/Jest configuration originally exist as template
strings in `.vscode/setup*` scripts. They are materialized into ordinary tracked
files so `npm test` does not depend on opening VS Code or launching popups.

Run `npm test -- --runInBand` and `npm run build --workspace client`.
Verified: both test suites pass (8 tests), including the localhost form attack,
unchanged saved email, invalid tokens, session binding, and other protected
writes. The client production build also passes. The initial MongoDB binary
download required a longer setup timeout. The HTTP attack was reproduced through
Supertest; an interactive browser run was not performed.

For the browser reproduction, follow Flow.md, save a legitimate recovery email,
then open the attacker page. Its form POST should return 403 and refreshing
Settings should still show the legitimate email.
