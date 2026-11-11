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
  const path = (config.url || '').split('?')[0]
  if (['get', 'head', 'options'].includes(method) ||
      ['/auth/login', '/auth/register'].includes(path)) return config

  // Fetch for each write so signing in again never reuses another session's token.
  const { data } = await api.get('/csrf-token')
  config.headers.set('X-CSRF-Token', data.csrfToken)
  return config
})
