import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token ----------------------------------------------------------
// The server rejects state-changing requests that lack a valid `x-csrf-token`
// header. We fetch the token from GET /csrf-token (our own origin is allowed by
// CORS to read it; an attacker's page is not) and attach it to every write.

const MUTATING = ['post', 'put', 'patch', 'delete']
// Pre-auth routes run before a session exists, so the server does not check them.
const CSRF_EXEMPT = ['/auth/login', '/auth/register']

let csrfToken = null
let csrfTokenPromise = null

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!csrfTokenPromise) {
    csrfTokenPromise = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { csrfTokenPromise = null })
  }
  return csrfTokenPromise
}

// Each token is tied to the session cookie, so drop it whenever the session changes.
export function resetCsrfToken() {
  csrfToken = null
}

const isMutating = (config) => MUTATING.includes((config.method || 'get').toLowerCase())
const isExempt = (config) => CSRF_EXEMPT.some(p => (config.url || '').startsWith(p))
const isAuthChange = (config) => (config.url || '').startsWith('/auth/')

api.interceptors.request.use(async (config) => {
  if (isMutating(config) && !isExempt(config)) {
    config.headers['x-csrf-token'] = await getCsrfToken()
  }
  return config
})

api.interceptors.response.use(
  (response) => {
    // login / register / logout replace the session cookie, so any cached token
    // is now bound to the wrong session.
    if (isMutating(response.config) && isAuthChange(response.config)) resetCsrfToken()
    return response
  },
  async (error) => {
    const config = error.config
    // A stale token (e.g. the session cookie changed) gives 403. Fetch a new one
    // and retry once.
    if (error.response?.status === 403 && config && isMutating(config) && !isExempt(config) && !config._csrfRetried) {
      config._csrfRetried = true
      resetCsrfToken()
      config.headers['x-csrf-token'] = await getCsrfToken()
      return api.request(config)
    }
    return Promise.reject(error)
  }
)
