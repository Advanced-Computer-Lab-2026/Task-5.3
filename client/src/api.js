import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token ------------------------------------------------------
// The server issues a token bound to the current session (GET /csrf-token).
// We must echo it in the `x-csrf-token` header on every state-changing request;
// a forged cross-site request can't read or guess it, so the server rejects it.

const SAFE_METHODS = ['get', 'head', 'options']
// Routes whose response changes the session, which invalidates the old token.
const SESSION_ROUTES = /\/auth\/(login|register|logout)$/

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

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method)) {
    config.headers.set('x-csrf-token', await getCsrfToken())
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    // The token is tied to the session cookie, so fetch a fresh one next time.
    if (SESSION_ROUTES.test(res.config.url || '')) csrfToken = null
    return res
  },
  async (error) => {
    const config = error.config
    const method = (config?.method || 'get').toLowerCase()
    // A stale token (e.g. the session changed) gives a 403. Refresh once and retry.
    if (error.response?.status === 403 && config && !config._csrfRetried && !SAFE_METHODS.includes(method)) {
      config._csrfRetried = true
      csrfToken = null
      config.headers.set('x-csrf-token', await getCsrfToken())
      return api.request(config)
    }
    return Promise.reject(error)
  }
)
