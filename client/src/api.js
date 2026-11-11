import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token -------------------------------------------------------
// The server issues a secret token at GET /csrf-token. Only our own origin can
// read that response, so we keep it in memory (never localStorage) and echo it in
// the `x-csrf-token` header on every state-changing request. A forged request
// from another site cannot know this value, so the server rejects it with 403.

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
// Pre-auth routes run before a session exists, so they don't need a token.
const PRE_AUTH = ['/auth/login', '/auth/register']
// These change the session (new/cleared JWT), which invalidates the old token.
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pending = null

export function clearCsrfToken() {
  csrfToken = null
}

export async function getCsrfToken(force = false) {
  if (csrfToken && !force) return csrfToken
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(({ data }) => (csrfToken = data.csrfToken))
      .finally(() => { pending = null })
  }
  return pending
}

const matches = (url, list) => list.some(p => (url || '').includes(p))

function setHeader(config, name, value) {
  if (config.headers && typeof config.headers.set === 'function') config.headers.set(name, value)
  else config.headers = { ...config.headers, [name]: value }
}

// Attach the token to every mutating request.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toUpperCase()
  if (SAFE_METHODS.has(method) || matches(config.url, PRE_AUTH)) return config
  setHeader(config, 'x-csrf-token', await getCsrfToken())
  return config
})

api.interceptors.response.use(
  (res) => {
    // Session changed -> the old token is bound to the old session; drop it.
    if (matches(res.config?.url, SESSION_CHANGING)) clearCsrfToken()
    return res
  },
  async (error) => {
    const { config, response } = error
    // Token missing/expired (e.g. after re-login): fetch a fresh one and retry once.
    if (response?.status === 403 && config && !config._csrfRetried &&
        !SAFE_METHODS.has((config.method || 'get').toUpperCase())) {
      config._csrfRetried = true
      setHeader(config, 'x-csrf-token', await getCsrfToken(true))
      return api(config)
    }
    return Promise.reject(error)
  }
)
