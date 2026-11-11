import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- Anti-CSRF token -------------------------------------------------------
// The server issues a session-bound token at GET /csrf-token. We echo it in the
// `x-csrf-token` header on every state-changing request. A cross-site attacker
// can neither read this token nor set this header, so forged requests get 403.

const SAFE_METHODS = ['get', 'head', 'options']
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

// The token is bound to the session, so forget it whenever the session changes.
export function clearCsrfToken() {
  csrfToken = null
}

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method)) {
    const token = csrfToken || await fetchCsrfToken()
    config.headers.set('x-csrf-token', token)
  }
  return config
})

api.interceptors.response.use(
  res => {
    // Login / register / logout start or end a session: the old token is stale.
    if (/\/auth\/(login|register|logout)$/.test(res.config.url || '')) clearCsrfToken()
    return res
  },
  async err => {
    const config = err.config
    // A 403 can mean our cached token is stale (e.g. session changed in another
    // tab). Fetch a fresh one and retry the request once.
    if (err.response?.status === 403 && config && !config._csrfRetried &&
        !SAFE_METHODS.includes((config.method || 'get').toLowerCase())) {
      config._csrfRetried = true
      clearCsrfToken()
      return api(config)
    }
    return Promise.reject(err)
  }
)
