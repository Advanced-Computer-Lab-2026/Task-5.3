import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- CSRF (double-submit cookie) ---
// The server pairs a token with an httpOnly cookie. We fetch the token and echo
// it back in the `x-csrf-token` header on every state-changing request. A
// cross-site attacker can neither read the token nor set this header.
const SAFE_METHODS = ['get', 'head', 'options']
const PRE_AUTH_URLS = ['/auth/login', '/auth/register']

let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    // Plain axios call (not `api`) so this request doesn't pass through the interceptors.
    const res = await api.request({ method: 'get', url: '/csrf-token', _skipCsrf: true })
    csrfToken = res.data.csrfToken
  }
  return csrfToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || config._skipCsrf) return config
  if (PRE_AUTH_URLS.some((u) => (config.url || '').includes(u))) return config
  config.headers['x-csrf-token'] = await getCsrfToken()
  return config
})

// The token is bound to the session, so drop it when the session changes
// (login / register / logout) and fetch a fresh one on the next write.
api.interceptors.response.use((res) => {
  const url = res.config?.url || ''
  if (['/auth/login', '/auth/register', '/auth/logout'].some((u) => url.includes(u))) {
    csrfToken = null
  }
  return res
})
