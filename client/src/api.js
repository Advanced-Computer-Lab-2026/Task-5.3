import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- CSRF protection -------------------------------------------------------
// The server issues a per-session token at GET /csrf-token. We fetch it once,
// cache it, and echo it in the `x-csrf-token` header on every state-changing
// request. A cross-site attacker cannot read this token, so cannot forge it.
let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  return csrfToken
}

// The token is bound to the session, so drop it whenever the session changes.
export function resetCsrfToken() {
  csrfToken = null
}

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists and are exempt on the server.
const EXEMPT_URLS = ['/auth/login', '/auth/register']

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || EXEMPT_URLS.includes(config.url)) return config
  const token = await getCsrfToken()
  config.headers.set ? config.headers.set('x-csrf-token', token) : (config.headers['x-csrf-token'] = token)
  return config
})

// A new session (login/register/logout) means a new token is required.
api.interceptors.response.use((res) => {
  if (EXEMPT_URLS.includes(res.config?.url) || res.config?.url === '/auth/logout') resetCsrfToken()
  return res
})
