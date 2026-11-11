import axios from 'axios'

// Send the session and CSRF cookies with requests to the API.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const safeMethods = new Set(['get', 'head', 'options'])
const preAuthRoutes = new Set(['/auth/login', '/auth/register'])

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  const path = (config.url || '').split('?')[0].replace(/\/$/, '')

  if (safeMethods.has(method) || preAuthRoutes.has(path)) return config

  // Fetch for each write so a token from a previous login is never reused.
  // This GET passes through the interceptor without fetching another token.
  const { data } = await api.get('/csrf-token')
  if (typeof data?.csrfToken !== 'string' || !data.csrfToken) {
    throw new Error('The server did not return a CSRF token')
  }

  config.headers['x-csrf-token'] = data.csrfToken
  return config
})
