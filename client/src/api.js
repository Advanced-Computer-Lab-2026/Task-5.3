import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF ----
// The server only accepts a state-changing request if it carries the CSRF token
// in the `x-csrf-token` header. We fetch the token from GET /csrf-token (only
// our own origin can read that response, thanks to CORS) and echo it on every write.
const SAFE_METHODS = ['get', 'head', 'options']
// Login/register run before a session exists, so they don't need a token.
const EXEMPT_URLS = ['/auth/login', '/auth/register']

let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  return csrfToken
}

// Call after login/register/logout: the token is bound to the session, so a new
// session needs a new token.
export function resetCsrfToken() {
  csrfToken = null
}

function setHeader(config, name, value) {
  if (config.headers && typeof config.headers.set === 'function') {
    config.headers.set(name, value)
  } else {
    config.headers = { ...(config.headers || {}), [name]: value }
  }
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (!SAFE_METHODS.includes(method) && !EXEMPT_URLS.some(u => url.includes(u))) {
    setHeader(config, 'x-csrf-token', await getCsrfToken())
  }
  return config
})

// If the token went stale (for example the session changed), fetch a fresh one
// and retry once.
api.interceptors.response.use(undefined, async (error) => {
  const config = error.config
  if (error.response?.status === 403 && config && !config._csrfRetried) {
    config._csrfRetried = true
    resetCsrfToken()
    setHeader(config, 'x-csrf-token', await getCsrfToken())
    return api(config)
  }
  return Promise.reject(error)
})
