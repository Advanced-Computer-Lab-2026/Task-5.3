import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token ------------------------------------------------------
// Every state-changing request must carry the token from GET /csrf-token in the
// `x-csrf-token` header. A forged cross-site request cannot read that token, nor
// can a plain HTML form set a custom header, so the server can tell our own
// requests apart from forged ones.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists and are exempt on the server.
const PRE_AUTH = ['/auth/login', '/auth/register']

let csrfToken = null
let pending = null

async function fetchCsrfToken() {
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

// The token is bound to the session, so it must be refreshed whenever the
// session changes (login, register, logout).
export function resetCsrfToken() {
  csrfToken = null
}

function needsToken(config) {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method)) return false
  return !PRE_AUTH.some(p => (config.url || '').includes(p))
}

api.interceptors.request.use(async (config) => {
  if (needsToken(config)) {
    const token = csrfToken || await fetchCsrfToken()
    config.headers.set('x-csrf-token', token)
  }
  return config
})

// If the token was rejected (for example it went stale after the session
// changed), fetch a fresh one and retry the request once.
api.interceptors.response.use(undefined, async (error) => {
  const { config, response } = error
  if (response?.status === 403 && config && needsToken(config) && !config._csrfRetried) {
    config._csrfRetried = true
    resetCsrfToken()
    const token = await fetchCsrfToken()
    config.headers.set('x-csrf-token', token)
    return api.request(config)
  }
  return Promise.reject(error)
})
