import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token -------------------------------------------------------
// The server requires an `x-csrf-token` header on every state-changing request.
// We fetch the token from GET /csrf-token (only our own origin can read that
// response, because of CORS) and echo it back in a header. A forged request
// from an attacker's page cannot read the token, so it cannot do the same.

const SAFE_METHODS = ['get', 'head', 'options']
// These run before a session exists (login/register), or change the session
// (login/register/logout). After any of them, the old token no longer matches,
// so we drop it and fetch a new one on the next write.
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pending = null

function fetchCsrfToken() {
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

function isPreAuth(url = '') {
  return url.includes('/auth/login') || url.includes('/auth/register')
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || isPreAuth(config.url)) return config

  const token = csrfToken || await fetchCsrfToken()
  config.headers['x-csrf-token'] = token
  return config
})

api.interceptors.response.use(
  (res) => {
    if (SESSION_CHANGING.some(p => (res.config.url || '').includes(p))) csrfToken = null
    return res
  },
  async (error) => {
    const { config, response } = error
    // A 403 on a write usually means the token is stale (e.g. the session
    // changed in another tab). Fetch a fresh token and retry exactly once.
    if (response?.status === 403 && config && !config._csrfRetried &&
        !SAFE_METHODS.includes((config.method || 'get').toLowerCase())) {
      config._csrfRetried = true
      csrfToken = null
      await fetchCsrfToken()
      return api(config)
    }
    return Promise.reject(error)
  }
)
