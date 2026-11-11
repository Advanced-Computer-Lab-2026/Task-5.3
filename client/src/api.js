import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes are exempt on the server, so no token is needed.
const EXEMPT_URLS = ['/auth/login', '/auth/register', '/csrf-token']

// Before every state-changing request, fetch a fresh CSRF token (the server also
// sets the matching csrf cookie) and echo it in the x-csrf-token header. Fetching
// each time keeps the token bound to the *current* session, so it stays valid
// across login / logout without any extra bookkeeping.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (SAFE_METHODS.includes(method) || EXEMPT_URLS.some((u) => url.includes(u))) {
    return config
  }
  const { data } = await api.get('/csrf-token')
  config.headers.set('x-csrf-token', data.csrfToken)
  return config
})
