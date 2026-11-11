import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// --- Anti-CSRF token ---
// Fetch the token once, then attach it to every POST/PUT/PATCH/DELETE
// in the x-csrf-token header.
const SAFE_METHODS = ['get', 'head', 'options']
let csrfToken = null
let pending = null

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

// The token belongs to one session, so forget it when the session changes.
export function clearCsrfToken() {
  csrfToken = null
}

function isAuthRoute(url = '') {
  return /\/auth\/(login|register|logout)/.test(url)
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method) && !isAuthRoute(config.url)) {
    const token = await getCsrfToken()
    config.headers = config.headers || {}
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', token)
    else config.headers['x-csrf-token'] = token
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    // Login/logout changes the session, so the old token is no longer valid.
    if (isAuthRoute(res.config?.url)) clearCsrfToken()
    return res
  },
  async (error) => {
    const { config, response } = error
    // If the token went stale, get a new one and retry once.
    const isCsrfError = /csrf/i.test(response?.data?.message || '')
    if (response?.status === 403 && isCsrfError && config && !config._csrfRetried && !isAuthRoute(config.url)) {
      config._csrfRetried = true
      clearCsrfToken()
      return api(config)
    }
    return Promise.reject(error)
  }
)