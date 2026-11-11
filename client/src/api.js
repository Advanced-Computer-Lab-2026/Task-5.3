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
  if (!['post', 'put', 'patch', 'delete'].includes(method)) return config
  const pathname = new URL(api.getUri(config), window.location.origin).pathname.replace(/\/$/, '')
  if (method === 'post' && ['/api/auth/login', '/api/auth/register'].includes(pathname)) return config

  try {
    const { data } = await api.get('/csrf-token')
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = data.csrfToken
    return config
  } catch (error) {
    return Promise.reject(error)
  }
})
