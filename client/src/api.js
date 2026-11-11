import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Fetch the readable double-submit token for every write. The CSRF cookie is
// sent automatically with credentials; the header proves the caller could read
// it from the app's origin. Login and registration are pre-session exceptions.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const isWrite = !['get', 'head', 'options'].includes(method)
  const isPreAuth = ['/auth/login', '/auth/register'].some(path => (config.url || '').includes(path))

  if (isWrite && !isPreAuth && !(config.headers?.['x-csrf-token'] || config.headers?.get?.('x-csrf-token'))) {
    const { data } = await api.get('/csrf-token')
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = data.csrfToken
  }
  return config
})
