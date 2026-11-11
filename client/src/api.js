import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF protection -------------------------------------------------------
// The server requires an anti-CSRF token on every state-changing request.
// We fetch it from GET /api/csrf-token (only our own origin can read that
// response, thanks to CORS) and echo it back in the `x-csrf-token` header.
// An attacker's page can do neither, so its forged requests get a 403.

const SAFE_METHODS = ['get', 'head', 'options']
let csrfToken = null

export async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

// The token is bound to the session, so drop it whenever the session changes
// (login, register, logout). A fresh one is fetched on the next write.
export function clearCsrfToken() {
  csrfToken = null
}

function setHeader(config, name, value) {
  if (config.headers && typeof config.headers.set === 'function') {
    config.headers.set(name, value)
  } else {
    config.headers = { ...(config.headers || {}), [name]: value }
  }
}

// Attach the token to every mutating request.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method)) {
    if (!csrfToken) await fetchCsrfToken()
    setHeader(config, 'x-csrf-token', csrfToken)
  }
  return config
})

// If the token was stale (e.g. the session changed), get a new one and retry once.
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const config = error.config
    if (error.response?.status === 403 && config && !config._csrfRetried) {
      config._csrfRetried = true
      await fetchCsrfToken()
      setHeader(config, 'x-csrf-token', csrfToken)
      return api(config)
    }
    return Promise.reject(error)
  }
)
