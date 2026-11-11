import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---------------- CSRF protection ----------------
// The server issues a CSRF token tied to the current session (JWT cookie).
// The attacker's site can't read it, so it can't forge write requests.

const SAFE_METHODS = ['get', 'head', 'options']
const PRE_AUTH = /\/auth\/(login|register)\/?$/          // no session yet -> exempt
const SESSION_CHANGE = /\/auth\/(login|register|logout)\/?$/

let csrfToken = null

// Fetch through the SAME api instance so cookies ride along
export async function refreshCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

export function clearCsrfToken() {
  csrfToken = null
}

// 1) Attach the token to every state-changing request (POST/PUT/PATCH/DELETE)
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || PRE_AUTH.test(config.url || '')) {
    return config
  }
  if (!csrfToken) await refreshCsrfToken()
  config.headers = config.headers || {}
  config.headers['x-csrf-token'] = csrfToken
  return config
})

api.interceptors.response.use(
  // 2) Login/register/logout change the JWT cookie -> the cached token is stale
  (response) => {
    if (SESSION_CHANGE.test(response.config.url || '')) clearCsrfToken()
    return response
  },
  // 3) Safety net: on a CSRF 403, fetch a fresh token and retry ONCE
  async (error) => {
    const { config, response } = error
    const isCsrfError =
      response?.status === 403 && /csrf/i.test(response?.data?.message || '')
    if (config && isCsrfError && !config._csrfRetried) {
      config._csrfRetried = true
      clearCsrfToken()
      await refreshCsrfToken()
      config.headers['x-csrf-token'] = csrfToken
      return api(config)
    }
    return Promise.reject(error)
  }
)

export default api