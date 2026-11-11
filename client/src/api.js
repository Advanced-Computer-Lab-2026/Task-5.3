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

function fetchCsrfToken() {
  // Concurrent writes share issuance so their responses cannot race to set cookies.
  if (!pendingToken) {
    pendingToken = api.get('/csrf-token').then(({ data }) => {
      if (!data.csrfToken) throw new Error('Could not obtain a CSRF token')
      return data.csrfToken
    }).finally(() => { pendingToken = undefined })
  }
  return pendingToken
}

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  if (!safeMethods.has(method) && !preAuthRoutes.has(config.url)) {
    // Fetch for the current session on each write; never reuse a previous login's token.
    config.headers.set('x-csrf-token', await fetchCsrfToken())
  }
  return config
})
