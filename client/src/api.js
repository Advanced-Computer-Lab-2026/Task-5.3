import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Fetch for each write so login/session changes cannot leave a cached stale token.
// Share an in-flight fetch so concurrent writes use the same cookie/token pair.
let pendingToken
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const path = (config.url || '').split('?')[0]
  if (['get', 'head', 'options'].includes(method) ||
      (method === 'post' && ['/auth/login', '/auth/register'].includes(path))) {
    return config
  }
  if (!pendingToken) {
    pendingToken = api.get('/csrf-token')
      .then(({ data }) => data.csrfToken)
      .finally(() => { pendingToken = undefined })
  }
  config.headers['x-csrf-token'] = await pendingToken
  return config
})
