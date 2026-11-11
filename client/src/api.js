import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- Anti-CSRF token ---------------------------------------------------------
// The server requires an `x-csrf-token` header on every state-changing request.
// We fetch the token from GET /csrf-token and echo it back on POST/PUT/PATCH/DELETE.
// An attacker's site can't do this: it can't read our token (CORS blocks reading
// the response) and a plain HTML form can't set custom headers.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists, so the server doesn't check them.
const EXEMPT_URLS = ['/auth/login', '/auth/register']

let csrfToken = null

async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

function needsCsrf(config) {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (SAFE_METHODS.includes(method)) return false
  if (url.includes('/csrf-token')) return false
  return !EXEMPT_URLS.some(path => url.includes(path))
}

api.interceptors.request.use(async (config) => {
  if (needsCsrf(config)) {
    const token = csrfToken || await fetchCsrfToken()
    config.headers = config.headers || {}
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', token)
    else config.headers['x-csrf-token'] = token
  }
  return config
})

api.interceptors.response.use(
  (response) => {
    // Logging in, registering or out changes the session, and the token is tied to
    // the session — so drop the cached one and fetch a fresh token next time.
    if ((response.config?.url || '').includes('/auth/')) csrfToken = null
    return response
  },
  async (error) => {
    const config = error.config
    // A 403 on a protected request usually means our token is stale (e.g. the session
    // changed). Fetch a new one and retry exactly once.
    if (error.response?.status === 403 && config && needsCsrf(config) && !config._csrfRetried) {
      config._csrfRetried = true
      csrfToken = null
      return api(config)
    }
    return Promise.reject(error)
  }
)
