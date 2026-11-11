import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})


// Before every write request, fetch a fresh CSRF token and send it in a header.
// GET requests are safe, so we skip them (this also avoids an endless loop,
// because the token request itself is a GET).
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (['get', 'head', 'options'].includes(method)) return config

  // Login/register run before a session exists, so they don't need a token.
  const url = config.url || ''
  if (url.includes('/auth/login') || url.includes('/auth/register')) return config

  const { data } = await api.get('/csrf-token')
  config.headers['x-csrf-token'] = data.csrfToken
  return config
})