import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF protection --------------------------------------------------------
// The server requires an anti-CSRF token on every state-changing request. We get
// it from GET /csrf-token and echo it back in the `x-csrf-token` header. An
// attacker's page can't read this value, so it can't forge the header.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists; the server doesn't check them.
const EXEMPT_URLS = ['/auth/login', '/auth/register']

let csrfToken = null
let pending = null

async function getCsrfToken(forceRefresh = false) {
  if (csrfToken && !forceRefresh) return csrfToken
  // Share one in-flight request if several writes fire at once.
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

// The token is bound to the session, so it must be re-fetched whenever the
// session changes (login / register / logout).
export function clearCsrfToken() {
  csrfToken = null
}

function needsToken(config) {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  return !SAFE_METHODS.includes(method) && !EXEMPT_URLS.some(u => url.includes(u))
}

api.interceptors.request.use(async (config) => {
  if (needsToken(config)) {
    const token = await getCsrfToken()
    config.headers = config.headers || {}
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', token)
    else config.headers['x-csrf-token'] = token
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    const url = res.config?.url || ''
    if (['/auth/login', '/auth/register', '/auth/logout'].some(u => url.includes(u))) {
      clearCsrfToken()
    }
    return res
  },
  async (error) => {
    // A 403 on a write usually means our cached token is stale (e.g. the
    // session changed). Fetch a fresh token and retry exactly once.
    const config = error.config
    if (error.response?.status === 403 && config && needsToken(config) && !config._csrfRetried) {
      config._csrfRetried = true
      clearCsrfToken()
      return api(config)
    }
    return Promise.reject(error)
  }
)
