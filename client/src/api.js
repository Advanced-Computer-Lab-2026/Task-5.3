import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF protection (double-submit cookie, csrf-csrf on the server) ----------
// Every state-changing request must echo the token from GET /csrf-token in the
// `x-csrf-token` header. A malicious site can ride our cookies, but it can neither
// read this token nor set the custom header.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes are exempt on the server, so no token is needed for them.
const EXEMPT_URLS = ['/auth/login', '/auth/register']

let csrfToken = null
let inflight = null

// Forget the cached token. Call after login / register / logout: the token is
// bound to the session, so a new session needs a new token.
export function resetCsrfToken() {
  csrfToken = null
  inflight = null
}

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!inflight) {
    inflight = api
      .get('/csrf-token')
      .then((res) => {
        csrfToken = res.data.csrfToken
        return csrfToken
      })
      .finally(() => {
        inflight = null
      })
  }
  return inflight
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method)) return config
  if (EXEMPT_URLS.some((u) => (config.url || '').endsWith(u))) return config

  config.headers['x-csrf-token'] = await getCsrfToken()
  return config
})

// If the token went stale, fetch a fresh one and retry the request once.
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const { response, config } = error
    const isCsrfFailure =
      response && response.status === 403 && /csrf/i.test(response.data?.message || '')
    if (isCsrfFailure && config && !config._csrfRetried) {
      config._csrfRetried = true
      resetCsrfToken()
      return api(config)
    }
    return Promise.reject(error)
  }
)