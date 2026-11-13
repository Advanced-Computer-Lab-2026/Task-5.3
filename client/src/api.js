import axios from 'axios'

// `withCredentials: true` makes the browser send the auth cookie (and the CSRF
// cookie) on cross-origin requests to the API.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF token handling ----
// The token is kept in memory only. It is bound to the session, so it is
// cleared whenever the session changes (login / register / logout).
let csrfToken = null

const SAFE_METHODS = ['get', 'head', 'options']
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout']

export async function getCsrfToken() {
  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  return csrfToken
}

export function clearCsrfToken() {
  csrfToken = null
}

// Attach x-csrf-token to every state-changing request.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  const isPreAuth = url.includes('/auth/login') || url.includes('/auth/register')

  if (!SAFE_METHODS.includes(method) && !url.includes('/csrf-token') && !isPreAuth) {
    const token = await getCsrfToken()
    config.headers = config.headers || {}
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', token)
    else config.headers['x-csrf-token'] = token
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    // Session changed -> old token is no longer valid.
    if (SESSION_CHANGING.some(p => (res.config?.url || '').includes(p))) clearCsrfToken()
    return res
  },
  async (error) => {
    const config = error.config
    // Token expired / session changed: fetch a fresh token and retry once.
    const isCsrfError = error.response?.status === 403 &&
      error.response?.data?.message === 'Invalid or missing CSRF token'
    if (isCsrfError && config && !config._csrfRetried) {
      config._csrfRetried = true
      clearCsrfToken()
      return api(config)
    }
    return Promise.reject(error)
  }
)
