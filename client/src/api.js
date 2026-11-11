import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF protection --------------------------------------------------------
// The server requires an `x-csrf-token` header on every state-changing request.
// We fetch the token from GET /api/csrf-token (only our own origin can read that
// response, because of CORS) and echo it back on each write. The attacker's
// forged form can't do either, so its request is rejected with 403.

const MUTATING_METHODS = ['post', 'put', 'patch', 'delete']
// These run before a session exists, so the server doesn't check them.
const CSRF_EXEMPT = ['/auth/login', '/auth/register']

let csrfToken = null
let pending = null

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

// The token is tied to the session, so throw it away whenever the session changes.
export function clearCsrfToken() {
  csrfToken = null
}

function isMutating(config) {
  return MUTATING_METHODS.includes((config.method || 'get').toLowerCase())
}

function isExempt(config) {
  return CSRF_EXEMPT.some(path => (config.url || '').includes(path))
}

api.interceptors.request.use(async (config) => {
  if (isMutating(config) && !isExempt(config)) {
    config.headers = config.headers || {}
    const token = await getCsrfToken()
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', token)
    else config.headers['x-csrf-token'] = token
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    // Logging in, registering or logging out starts a new session, so the
    // old token is no longer valid.
    if (isMutating(res.config) && /\/auth\/(login|register|logout)/.test(res.config.url || '')) {
      clearCsrfToken()
    }
    return res
  },
  async (error) => {
    const config = error.config
    // If the token was stale (e.g. the session changed), get a fresh one and retry once.
    if (error.response?.status === 403 && config && isMutating(config) && !isExempt(config) && !config._csrfRetried) {
      config._csrfRetried = true
      clearCsrfToken()
      return api(config)
    }
    return Promise.reject(error)
  }
)
