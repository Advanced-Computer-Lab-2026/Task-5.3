import axios from 'axios'

// Send and accept session and CSRF cookies on requests to the API.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const safeMethods = new Set(['get', 'head', 'options'])
const preAuthPaths = new Set(['/auth/login', '/auth/register'])
let pendingToken

api.interceptors.request.use(async (config) => {
  const method = config.method?.toLowerCase() || 'get'
  if (safeMethods.has(method)) return config

  const base = new URL(api.defaults.baseURL)
  const target = new URL(api.getUri(config))
  if (target.origin !== base.origin || !target.pathname.startsWith(base.pathname + '/')) {
    return config
  }
  const path = target.pathname.slice(base.pathname.length).replace(/\/$/, '').toLowerCase()
  if (method === 'post' && preAuthPaths.has(path)) return config

  // Share a token request between concurrent writes so they use the same cookie.
  pendingToken ??= api.get('/csrf-token')
    .then(({ data }) => data.csrfToken)
    .finally(() => { pendingToken = undefined })
  config.headers.set('x-csrf-token', await pendingToken)
  return config
})
