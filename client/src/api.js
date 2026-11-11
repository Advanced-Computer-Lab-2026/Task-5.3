import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so the browser handles the session cookie.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const safeMethods = new Set(['get', 'head', 'options'])
const preAuthRoutes = new Set(['/auth/login', '/auth/register'])
let pendingCsrfToken

api.interceptors.request.use(async config => {
  const method = config.method || 'get'
  if (safeMethods.has(method) || (method === 'post' && preAuthRoutes.has(config.url))) {
    return config
  }

  // Concurrent writes share the same token request and cookie.
  pendingCsrfToken ??= api.get('/csrf-token')
    .then(({ data }) => data.csrfToken)
    .finally(() => { pendingCsrfToken = undefined })

  config.headers.set('x-csrf-token', await pendingCsrfToken)
  return config
})
