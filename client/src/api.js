import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Acquire a session-bound token before every write, then echo it in a header.
// Login and registration run before a session exists and are intentionally exempt.
api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  const isMutation = !['get', 'head', 'options'].includes(method)
  const route = (config.url || '').replace(/^\//, '')
  const isPreAuth = route === 'auth/login' || route === 'auth/register'

  if (isMutation && !isPreAuth) {
    const { data } = await api.get('/csrf-token')
    config.headers = config.headers || {}
    if (typeof config.headers.set === 'function') config.headers.set('x-csrf-token', data.csrfToken)
    else config.headers['x-csrf-token'] = data.csrfToken
  }

  return config
})
