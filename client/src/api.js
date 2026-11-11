import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---------------------------------------------------------------------------
// Anti-CSRF token handling (pairs with server/src/middleware/csrf.js).
//
// The server requires every state-changing request to echo a per-session CSRF
// token in the `x-csrf-token` header. We fetch it from GET /csrf-token (our own
// origin is allowed by CORS to read the response; an attacker's page is not)
// and attach it to every mutating request. Safe methods and the pre-auth routes
// (login/register) do not need it.
// ---------------------------------------------------------------------------

const SAFE_METHODS = new Set(['get', 'head', 'options'])
const PRE_AUTH_PATHS = ['/auth/login', '/auth/register']
// Requests after which the session (auth cookie) changes, so the old CSRF token
// — which is bound to the session — is no longer valid.
const SESSION_CHANGING_PATHS = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pendingToken = null

function matches(url, paths) {
  return paths.some(p => (url || '').endsWith(p))
}

function needsCsrf(config) {
  const method = (config.method || 'get').toLowerCase()
  return !SAFE_METHODS.has(method) && !matches(config.url, PRE_AUTH_PATHS)
}

async function getCsrfToken({ refresh = false } = {}) {
  if (refresh) csrfToken = null
  if (csrfToken) return csrfToken
  if (!pendingToken) {
    pendingToken = api.get('/csrf-token')
      .then(res => (csrfToken = res.data.csrfToken))
      .finally(() => { pendingToken = null })
  }
  return pendingToken
}

function setHeader(config, name, value) {
  if (config.headers && typeof config.headers.set === 'function') config.headers.set(name, value)
  else config.headers = { ...(config.headers || {}), [name]: value }
}

export function clearCsrfToken() {
  csrfToken = null
}

api.interceptors.request.use(async config => {
  if (needsCsrf(config)) {
    setHeader(config, 'x-csrf-token', await getCsrfToken())
  }
  return config
})

api.interceptors.response.use(
  res => {
    if (matches(res.config?.url, SESSION_CHANGING_PATHS)) clearCsrfToken()
    return res
  },
  async err => {
    const config = err.config
    // A stale token (e.g. the session changed) is rejected with 403: fetch a
    // fresh one and retry the request exactly once.
    if (err.response?.status === 403 && config && needsCsrf(config) && !config._csrfRetried) {
      config._csrfRetried = true
      setHeader(config, 'x-csrf-token', await getCsrfToken({ refresh: true }))
      return api.request(config)
    }
    if (config && matches(config.url, SESSION_CHANGING_PATHS)) clearCsrfToken()
    return Promise.reject(err)
  }
)
