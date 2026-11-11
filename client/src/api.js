import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Read the token from JSON, not document.cookie: cookies are shared across ports.
// Fetch before each write so login/logout session changes are picked up.
let pendingCsrfToken
api.interceptors.request.use(async (config) => {
  if (!['get', 'head', 'options'].includes((config.method || 'get').toLowerCase())) {
    if (!pendingCsrfToken) {
      pendingCsrfToken = api.get('/csrf-token')
        .then(({ data }) => data.csrfToken)
        .finally(() => { pendingCsrfToken = undefined })
    }
    config.headers['x-csrf-token'] = await pendingCsrfToken
  }
  return config
})
