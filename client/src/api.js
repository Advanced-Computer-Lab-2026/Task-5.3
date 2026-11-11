import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- CSRF protection --------------------------------------------------------
// The server requires an anti-CSRF token in the `x-csrf-token` header on every
// state-changing request. We fetch it once from GET /csrf-token, cache it, and
// attach it to every non-safe request. A cross-site attacker can't read this
// token, so their forged requests are rejected with 403.
const SAFE_METHODS = ['get', 'head', 'options']
let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  return csrfToken
}

// The token is bound to the session, so drop it whenever the session changes.
export function clearCsrfToken() {
  csrfToken = null
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method)) {
    const token = await getCsrfToken()
    if (typeof config.headers?.set === 'function') {
      config.headers.set('x-csrf-token', token)
    } else {
      config.headers = { ...config.headers, 'x-csrf-token': token }
    }
  }
  return config
})

// If the token went stale (e.g. session changed), fetch a fresh one and retry once.
api.interceptors.response.use(undefined, async (error) => {
  const config = error.config
  const isCsrfError = error.response?.status === 403 &&
    /csrf/i.test(error.response?.data?.message || '')
  if (isCsrfError && config && !config._csrfRetried) {
    config._csrfRetried = true
    clearCsrfToken()
    return api(config)
  }
  return Promise.reject(error)
})
