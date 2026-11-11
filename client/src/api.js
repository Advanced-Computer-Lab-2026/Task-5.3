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
// We fetch the token from GET /csrf-token (which also sets its companion
// httpOnly cookie), keep it in memory, and attach it to mutating requests.
// An attacker's page can't do this: it can't read our responses (CORS) and an
// HTML form can't set custom headers.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes are exempt on the server — no session exists yet.
const EXEMPT_URLS = ['/auth/login', '/auth/register']

let csrfToken = null
let csrfTokenPromise = null

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!csrfTokenPromise) {
    csrfTokenPromise = api.get('/csrf-token')
      .then(res => {
        csrfToken = res.data.csrfToken
        return csrfToken
      })
      .finally(() => { csrfTokenPromise = null })
  }
  return csrfTokenPromise
}

// The token is bound to the session, so forget it whenever the session changes
// (login, register, logout).
export function resetCsrfToken() {
  csrfToken = null
}

function needsCsrf(config) {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method)) return false
  return !EXEMPT_URLS.some(u => (config.url || '').includes(u))
}

api.interceptors.request.use(async config => {
  if (needsCsrf(config)) {
    config.headers = config.headers || {}
    const token = await getCsrfToken()
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', token)
    else config.headers['x-csrf-token'] = token
  }
  return config
})

// If the token went stale (e.g. the session changed in another tab), fetch a
// fresh one and retry the request once.
api.interceptors.response.use(undefined, async error => {
  const config = error?.config
  const isCsrfError = error?.response?.status === 403 &&
    /csrf/i.test(error?.response?.data?.message || '')
  if (isCsrfError && config && needsCsrf(config) && !config._csrfRetried) {
    config._csrfRetried = true
    resetCsrfToken()
    return api.request(config)
  }
  return Promise.reject(error)
})
