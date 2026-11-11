import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---------------------------------------------------------------------------
// Anti-CSRF token
//
// The server requires an `x-csrf-token` header on every state-changing request.
// We fetch the token from GET /csrf-token (only our own origin can read that
// response, thanks to CORS) and echo it back as a header. An attacker's page
// can neither read the token nor make a plain <form> send a custom header, so
// its forged requests are rejected with 403.
// ---------------------------------------------------------------------------

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes are exempt on the server (no session exists yet).
const EXEMPT_URLS = ['/auth/login', '/auth/register']
// These change the session (the auth cookie), so the old token is no longer valid.
const SESSION_CHANGING_URLS = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pendingToken = null

function urlMatches(url, list) {
  return list.some(u => (url || '').includes(u))
}

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  // Share one in-flight request between concurrent writes.
  if (!pendingToken) {
    pendingToken = api.get('/csrf-token')
      .then(res => {
        csrfToken = res.data.csrfToken
        return csrfToken
      })
      .finally(() => { pendingToken = null })
  }
  return pendingToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || urlMatches(config.url, EXEMPT_URLS)) {
    return config
  }
  config.headers['x-csrf-token'] = await getCsrfToken()
  return config
})

api.interceptors.response.use(
  (res) => {
    // Login/register/logout swap the session, so drop the token bound to the old one.
    if (urlMatches(res.config?.url, SESSION_CHANGING_URLS)) csrfToken = null
    return res
  },
  async (error) => {
    const { config, response } = error
    // A stale token (e.g. the session changed in another tab) -> fetch a fresh
    // one and retry the request once.
    if (
      response?.status === 403 &&
      /csrf/i.test(response.data?.message || '') &&
      config && !config._csrfRetried
    ) {
      config._csrfRetried = true
      csrfToken = null
      return api(config)
    }
    return Promise.reject(error)
  }
)
