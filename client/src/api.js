import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Anti-CSRF token, kept in memory only. It is fetched from our own API, which a
// cross-site page cannot read, and echoed back in a header on every write.
let csrfToken = null

const SAFE_METHODS = ['get', 'head', 'options']
const PRE_AUTH = ['/auth/login', '/auth/register']

async function getCsrfToken() {
  if (!csrfToken) {
    const res = await api.get('/csrf-token')
    csrfToken = res.data.csrfToken
  }
  return csrfToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (!SAFE_METHODS.includes(method) && !PRE_AUTH.some((p) => url.includes(p))) {
    config.headers['x-csrf-token'] = await getCsrfToken()
  }
  return config
})

// The token is bound to the login session, so drop it whenever the session changes.
api.interceptors.response.use((res) => {
  const url = res.config?.url || ''
  if (['/auth/login', '/auth/register', '/auth/logout'].some((p) => url.includes(p))) {
    csrfToken = null
  }
  return res
})