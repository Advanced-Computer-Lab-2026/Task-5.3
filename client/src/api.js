import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const stateChangingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const preAuthRoutes = new Set(['/auth/login', '/auth/register'])

api.interceptors.request.use(async config => {
  const method = config.method?.toUpperCase()
  const url = config.url?.split('?')[0]

  if (!stateChangingMethods.has(method) || preAuthRoutes.has(url)) return config

  const { data } = await api.get('/csrf-token')
  config.headers['x-csrf-token'] = data.csrfToken
  return config
})
