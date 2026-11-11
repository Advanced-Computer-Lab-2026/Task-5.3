import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token -------------------------------------------------------
// The server (csrf-csrf, double-submit cookie) requires every state-changing
// request to echo a secret token in the `x-csrf-token` header. We fetch it from
// GET /csrf-token and attach it to every mutating request. An attacker's page
// can't read this token or set a custom header on a forged form, so its
// requests get rejected with 403.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth / session-changing routes: the token is bound to the session, so it
// must be refreshed after any of these.
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pending = null

export async function getCsrfToken(force = false) {
  if (csrfToken && !force) return csrfToken
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

export function clearCsrfToken() {
  csrfToken = null
}

const isMutating = (config) => !SAFE_METHODS.includes((config.method || 'get').toLowerCase())
const isSessionChanging = (config) => SESSION_CHANGING.some(p => (config.url || '').includes(p))

api.interceptors.request.use(async (config) => {
  if (isMutating(config)) {
    const token = await getCsrfToken()
    config.headers = config.headers || {}
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', token)
    else config.headers['x-csrf-token'] = token
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    // The session (and thus the token binding) changed — fetch a fresh token next time.
    if (isSessionChanging(res.config)) clearCsrfToken()
    return res
  },
  async (error) => {
    const config = error.config
    // A stale token (e.g. the session changed in another tab): refresh once and retry.
    if (error.response?.status === 403 && config && isMutating(config) && !config._csrfRetried) {
      config._csrfRetried = true
      await getCsrfToken(true)
      return api(config)
    }
    return Promise.reject(error)
  }
)
