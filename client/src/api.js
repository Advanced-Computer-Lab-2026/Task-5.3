import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toUpperCase()
  const path = (config.url || '').split('?')[0].replace(/\/+$/, '')
  const safeMethods = ['GET', 'HEAD', 'OPTIONS']
  const preAuthRoutes = ['/auth/login', '/auth/register']

  if (safeMethods.includes(method) || preAuthRoutes.includes(path)) {
    return config
  }

  const { data } = await api.get('/csrf-token')
  config.headers = config.headers || {}
  config.headers['x-csrf-token'] = data.csrfToken
  return config
})
