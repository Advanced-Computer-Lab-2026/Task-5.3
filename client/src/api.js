import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- CSRF protection -------------------------------------------------------
// The server requires an anti-CSRF token in the `x-csrf-token` header on every
// state-changing request. We fetch it once from GET /csrf-token and cache it.
const MUTATING = ['post', 'put', 'patch', 'delete']
let csrfToken = null
let pending = null

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  // Use the same `api` instance (not bare axios) so credentials and baseURL apply.
  // It's a GET, so this interceptor won't try to attach a token to it.
  pending ??= api.get('/csrf-token')
    .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
    .finally(() => { pending = null })
  return pending
}

// The token is bound to the session (auth cookie), so drop it whenever the
// session changes (login, register, logout).
export function clearCsrfToken() {
  csrfToken = null
}

api.interceptors.request.use(async (config) => {
  if (MUTATING.includes((config.method || 'get').toLowerCase())) {
    config.headers['x-csrf-token'] = await getCsrfToken()
  }
  return config
})

// If the token went stale (403), fetch a fresh one and retry once.
api.interceptors.response.use(undefined, async (error) => {
  const config = error.config
  if (error.response?.status === 403 && config && !config._csrfRetried &&
      MUTATING.includes((config.method || 'get').toLowerCase())) {
    config._csrfRetried = true
    clearCsrfToken()
    return api(config)
  }
  return Promise.reject(error)
})
