import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const safeMethods = new Set(['get', 'head', 'options'])
const preAuthRoutes = new Set(['/auth/login', '/auth/register'])
let pendingToken

api.interceptors.request.use(async config => {
  const method = config.method
  const path = config.url.split('?')[0].replace(/\/$/, '').toLowerCase()
  if (safeMethods.has(method) || (method === 'post' && preAuthRoutes.has(path))) {
    return config
  }

  // Share an in-flight fetch so concurrent writes use the same cookie and token.
  pendingToken ??= api.get('/csrf-token')
    .then(({ data }) => data.csrfToken)
    .finally(() => { pendingToken = undefined })

  config.headers.set('x-csrf-token', await pendingToken)
  return config
})
