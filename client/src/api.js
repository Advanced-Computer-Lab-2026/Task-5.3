import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ─── CSRF token management ────────────────────────────────────────────────────
//
// We fetch the token lazily on the first mutating request, then cache it for
// the rest of the session. The double-submit-cookie pattern requires that the
// token value sent in the x-csrf-token header matches what the server signed
// into the CSRF cookie — something a cross-site attacker cannot do because
// it cannot read our cookies (SameSite + HttpOnly) or our CORS-restricted
// response body.

let _csrfToken = null;

async function getCsrfToken() {
  if (_csrfToken) return _csrfToken;
  const res = await api.get('/csrf-token');
  _csrfToken = res.data.csrfToken;
  return _csrfToken;
}

// Intercept every request that changes state (anything that isn't GET/HEAD/OPTIONS)
// and attach the CSRF token in the x-csrf-token header before it goes out.
const SAFE_METHODS = new Set(['get', 'head', 'options']);

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  if (!SAFE_METHODS.has(method)) {
    const token = await getCsrfToken();
    config.headers = config.headers || {};
    config.headers['x-csrf-token'] = token;
  }
  return config;
});
