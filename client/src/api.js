import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Anti-CSRF: every state-changing request must echo a token from
// GET /csrf-token in the `x-csrf-token` header. An attacker's page can't read
// that token, so it can't forge the header.
const SAFE_METHODS = ['get', 'head', 'options']
let csrfToken = null

async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

const isAuthRoute = url => (url || '').startsWith('/auth/')

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || isAuthRoute(config.url)) return config
  const token = csrfToken || await fetchCsrfToken()
  config.headers.set('x-csrf-token', token)
  return config
})

api.interceptors.response.use(
  res => {
    // Login/register/logout change the session the token is bound to.
    if (isAuthRoute(res.config.url)) csrfToken = null
    return res
  },
  async err => {
    const config = err.config
    // A stale token (e.g. after re-login) is rejected with 403: refresh it once and retry.
    if (err.response?.status === 403 && config && !config._csrfRetried && !isAuthRoute(config.url)) {
      config._csrfRetried = true
      csrfToken = null
      return api(config)
    }
    return Promise.reject(err)
  }
)
