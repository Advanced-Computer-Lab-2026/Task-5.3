# Flow — Verifying the CSRF Defense

This project demonstrates a CSRF attack against an account recovery-email endpoint. The endpoint is now protected with a session-bound token using the `csrf-csrf` double-submit-cookie pattern. The attack page remains intentionally unchanged so you can verify that its forged request is rejected.

## 0. Prerequisites and setup

From the project root (`Task-5.3/`), install dependencies and configure `server/.env` if needed:

```ini
PORT=4000
MONGO_URI=<your MongoDB Atlas connection string>
JWT_SECRET=<a long random secret>
JWT_EXPIRES_IN=7d
CSRF_SECRET=<optional separate long random secret; defaults to JWT_SECRET>
```

`server/.env` is ignored by Git. Start the app:

```bash
npm install
npm run dev
```

The API runs at `http://localhost:4000`; the client runs at `http://localhost:5175`.

## 1. Confirm the authenticated baseline

1. Register or log in through the client and open Settings.
2. Set a recovery email you recognize and save it. The client obtains a CSRF token from `GET /api/csrf-token` and sends it in the `x-csrf-token` header on writes.
3. Confirm the saved value appears in Settings.

## 2. Run the attacker page

In another terminal, start the attacker site:

```bash
cd attacker
npm install
npm start
```

In the same browser profile, open `http://localhost:1337`. The page auto-submits a hidden HTML form to `POST http://localhost:4000/api/settings/recovery-email` with `recoveryEmail=attacker@evil.com`.

## 3. Verify the forged request is rejected

In DevTools Network, inspect the form POST. It should return **403** because the form does not carry the required `x-csrf-token` header. Since both hosts are `localhost`, the browser may include the `SameSite=Lax` authentication cookie; that does not satisfy the CSRF check. The request is cross-origin, and the attacker page cannot read the token response from the client origin or set the custom header on a plain form submission.

Return to the app and reload Settings. The recovery email should still be the value you set in step 1. The attack page targets a hidden iframe, does not navigate the top-level app tab, and does not call logout.

If the app displays Login, do not infer from that screen alone that CSRF protection logged you out. The client restores auth by requesting `GET /api/auth/me`; its AuthContext sets the user to null on any error from that request, and ProtectedRoute then displays Login. Check that request's status and response in DevTools. The forged POST should be 403, and the server clears auth and CSRF cookies only in the authenticated logout endpoint.

## 4. What the protection checks

- `GET /api/csrf-token` is authenticated and returns a token for the current login session. The CSRF cookie is httpOnly; the client receives the token in the JSON response and holds it in memory.
- Authenticated state-changing requests, including settings, item, user, and logout writes, require the token in `x-csrf-token`.
- Safe GET, HEAD, and OPTIONS requests are CSRF-exempt. Login and registration remain pre-authentication routes and do not require a token.
- CORS and SameSite are useful layers but do not replace the token check in this localhost demonstration.

## 5. Automated verification

From the project root:

```bash
npm test
npm run build --workspace client
```

The integration suite uses an in-memory MongoDB and checks legitimate updates, missing and invalid tokens, and that rejected requests do not change settings. It also covers registration, login, logout, and authenticated reads. The suite should pass with dependencies installed.

The project requires Node.js 18 or newer. On first test run, `mongodb-memory-server` may need to download a MongoDB binary.