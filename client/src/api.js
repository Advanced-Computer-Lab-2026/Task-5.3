import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token -------------------------------------------------------
// The server only accepts a state-changing request if it carries the per-session
// CSRF token in the `x-csrf-token` header. Our own JS can fetch the token (same
// origin as allowed by CORS) and set the header; an attacker's page can do neither.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes: there is no session yet, so there is no token to send.
const CSRF_EXEMPT = ['/auth/login', '/auth/register']
const CSRF_ERROR_CODE = 'EBADCSRFTOKEN'

let csrfToken = null
let pending = null

// Fetch (once) and cache the token for the current session.
export function fetchCsrfToken() {
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(({ data }) => (csrfToken = data.csrfToken))
      .finally(() => { pending = null })
  }
  return pending
}

// The token is tied to the session, so drop it whenever the session changes
// (login, register, logout).
export function clearCsrfToken() {
  csrfToken = null
}

function needsCsrfToken(config) {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  return !SAFE_METHODS.includes(method) && !CSRF_EXEMPT.some(p => url.startsWith(p))
}

// Attach the token to every mutating request.
api.interceptors.request.use(async (config) => {
  if (needsCsrfToken(config)) {
    const token = csrfToken ?? await fetchCsrfToken()
    config.headers.set('x-csrf-token', token)
  }
  return config
})

// If the token went stale (e.g. the session changed in another tab), get a
// fresh one and retry the request once.
api.interceptors.response.use(undefined, async (error) => {
  const { config, response } = error
  if (
    response?.status === 403 &&
    response.data?.code === CSRF_ERROR_CODE &&
    config && !config._csrfRetried
  ) {
    config._csrfRetried = true
    clearCsrfToken()
    return api(config)
  }
  throw error
})
