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
// state-changing request. We fetch it from GET /csrf-token (our own origin can
// read that response; an attacker's page cannot) and echo it on each write.

const UNSAFE_METHODS = new Set(['post', 'put', 'patch', 'delete'])
// Logging in/out changes the session, and the token is bound to the session,
// so after these calls the cached token is stale and must be refetched.
const SESSION_CHANGING = /\/auth\/(login|register|logout)$/

let csrfToken = null
let pendingToken = null

function getCsrfToken() {
  if (csrfToken) return Promise.resolve(csrfToken)
  if (!pendingToken) {
    pendingToken = api.get('/csrf-token')
      .then(res => (csrfToken = res.data.csrfToken))
      .finally(() => { pendingToken = null })
  }
  return pendingToken
}

api.interceptors.request.use(async (config) => {
  if (UNSAFE_METHODS.has((config.method || 'get').toLowerCase())) {
    config.headers['x-csrf-token'] = await getCsrfToken()
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    if (SESSION_CHANGING.test(res.config.url || '')) csrfToken = null
    return res
  },
  async (err) => {
    const { config, response } = err
    // A stale token (e.g. the session cookie expired and was reissued): grab a
    // fresh one and retry the request once.
    if (response?.status === 403 && config && !config._csrfRetried &&
        /csrf/i.test(response.data?.message || '')) {
      csrfToken = null
      config._csrfRetried = true
      return api(config)
    }
    return Promise.reject(err)
  }
)
