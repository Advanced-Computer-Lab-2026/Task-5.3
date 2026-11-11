import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})
const safeMethods = new Set(['get', 'head', 'options'])
const preAuthPaths = new Set(['/auth/login', '/auth/register'])

let pendingCsrfToken

api.interceptors.request.use(async config => {
  const method = (config.method ?? 'get').toLowerCase()

  if (
    safeMethods.has(method) ||
    (method === 'post' && preAuthPaths.has(config.url))
  ) {
    return config
  }

  pendingCsrfToken ??= api.get('/csrf-token')
    .then(({ data }) => data.csrfToken)
    .finally(() => {
      pendingCsrfToken = undefined
    })

  config.headers.set('x-csrf-token', await pendingCsrfToken)
  return config
})
