import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF token handling ---------------------------------------------------
// Safe methods never change state, and login/register run before a session
// exists, so none of those need a token.
const SAFE_METHODS = ['get', 'head', 'options']
const PRE_AUTH = ['/auth/login', '/auth/register']
// After these the session cookie changes, so the cached token is no longer valid.
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout']

const urlMatches = (url, list) => list.some((p) => (url || '').endsWith(p))

let csrfToken = null
let inFlight = null

// One shared request even if several writes start at once.
function fetchCsrfToken() {
  if (!inFlight) {
    inFlight = api
      .get('/csrf-token')
      .then((res) => {
        csrfToken = res.data.csrfToken
        return csrfToken
      })
      .finally(() => {
        inFlight = null
      })
  }
  return inFlight
}

// Echo the token in a header on every state-changing request. A forged request
// from another site can neither read this token nor set this header.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || urlMatches(config.url, PRE_AUTH)) return config

  const token = csrfToken || (await fetchCsrfToken())
  config.headers.set('x-csrf-token', token)
  return config
})

api.interceptors.response.use(
  (res) => {
    if (urlMatches(res.config?.url, SESSION_CHANGING)) csrfToken = null
    return res
  },
  async (error) => {
    const { config, response } = error
    const method = (config?.method || 'get').toLowerCase()
    // A 403 on a write usually means the cached token is stale (new session or
    // another tab minted a newer one). Fetch a fresh token and retry exactly once.
    if (response?.status === 403 && config && !config._csrfRetried && !SAFE_METHODS.includes(method)) {
      config._csrfRetried = true
      csrfToken = null
      return api(config)
    }
    return Promise.reject(error)
  }
)
