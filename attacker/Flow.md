\# CSRF Attack Flow



\## Normal request

1\. The victim logs in and receives an HttpOnly authentication cookie.

2\. The client requests a CSRF token from `/api/csrf-token`.

3\. The server generates a session-specific CSRF token and sets the CSRF cookie.

4\. The client sends the token in the `x-csrf-token` header when updating the recovery email.

5\. The server validates the token and accepts the request.



\## Forged request

1\. An attacker attempts to submit a recovery-email update using the victim's authentication cookie.

2\. The attacker cannot provide the valid CSRF token in the required header.

3\. The server rejects the request with HTTP 403.

4\. The victim's recovery email remains unchanged.



\## Result

The CSRF protection prevents the forged state-changing request.

