import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- Anti-CSRF token -------------------------------------------------------
// The server rejects every state-changing request that does not echo a CSRF
// token in the `x-csrf-token` header. We fetch that token from the API (only our
// own origin is allowed to read the response, thanks to CORS), keep it in memory
// and attach it to each write. A malicious site can do neither.

const MUTATING_METHODS = ['post', 'put', 'patch', 'delete']
// Login and register run before a session exists, so the server exempts them.
const isPreAuth = (url = '') => /\/auth\/(login|register)$/.test(url)
// These change which session we are in, so any cached token becomes stale.
const changesSession = (url = '') => /\/auth\/(login|register|logout)$/.test(url)

let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const res = await api.get('/csrf-token')
    csrfToken = res.data.csrfToken
  }
  return csrfToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (MUTATING_METHODS.includes(method) && !isPreAuth(config.url)) {
    config.headers['x-csrf-token'] = await getCsrfToken()
  }
  return config
})

api.interceptors.response.use(
  (response) => {
    // The token is bound to the session: drop it when the session changes.
    if (changesSession(response.config?.url)) csrfToken = null
    return response
  },
  async (error) => {
    const config = error.config
    // A 403 on a write most likely means our cached token went stale (e.g. the
    // session was renewed in another tab). Fetch a fresh one and retry once.
    const method = (config?.method || 'get').toLowerCase()
    if (
      error.response?.status === 403 &&
      config && !config._csrfRetried &&
      MUTATING_METHODS.includes(method) && !isPreAuth(config.url)
    ) {
      config._csrfRetried = true
      csrfToken = null
      return api(config)
    }
    return Promise.reject(error)
  }
)
