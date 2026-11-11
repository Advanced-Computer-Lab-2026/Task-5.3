import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF token handling ----
// The server issues an anti-CSRF token from GET /csrf-token. We echo it back in
// the `x-csrf-token` header on every state-changing request. An attacker's page
// can't read this token, so it can't forge a valid request.
const SAFE_METHODS = ['get', 'head', 'options']
let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  return csrfToken
}

// The token is bound to the session, so drop it whenever the session changes
// (login / register / logout). The next write fetches a fresh one.
export function resetCsrfToken() {
  csrfToken = null
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method)) {
    config.headers.set('x-csrf-token', await getCsrfToken())
  }
  return config
})

// If the token went stale (e.g. the session changed in another tab), fetch a new
// one and retry the request once.
api.interceptors.response.use(undefined, async (error) => {
  const { config, response } = error
  if (response?.status === 403 && config && !config._csrfRetried) {
    config._csrfRetried = true
    resetCsrfToken()
    return api(config)
  }
  return Promise.reject(error)
})
