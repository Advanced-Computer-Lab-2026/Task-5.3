import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const csrfExemptPaths = ['/auth/login', '/auth/register']
const mutatingMethods = new Set(['post', 'put', 'patch', 'delete'])

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (!mutatingMethods.has(method) || csrfExemptPaths.some(path => url.includes(path))) {
    return config
  }

  const { data } = await api.get('/csrf-token')
  config.headers['x-csrf-token'] = data.csrfToken
  return config
})
