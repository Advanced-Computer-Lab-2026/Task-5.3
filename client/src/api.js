import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const pathname = new URL(api.getUri(config), 'http://localhost').pathname.replace(/\/$/, '')
  const preAuth = method === 'post' && ['/api/auth/login', '/api/auth/register'].includes(pathname)
  if (['get', 'head', 'options'].includes(method) || preAuth) return config

  const { data } = await api.get('/csrf-token')
  if (typeof data?.csrfToken !== 'string' || !data.csrfToken.trim()) {
    throw new Error('Could not obtain a CSRF token')
  }
  config.headers.set('x-csrf-token', data.csrfToken)
  return config
})
