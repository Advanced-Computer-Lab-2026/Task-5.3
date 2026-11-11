
import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Methods that can change data
const protectedMethods = ['post', 'put', 'patch', 'delete']

// Routes that do not require CSRF protection
const exemptRoutes = ['/auth/login', '/auth/register']

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''

  // Safe requests do not need a CSRF token
  if (!protectedMethods.includes(method)) {
    return config
  }

  // Login and registration happen before authentication
  if (exemptRoutes.some(route => url.split('?')[0] === route)) {
    return config
  }

  // Fetch a CSRF token from the server
  const response = await api.get('/csrf-token')
  const csrfToken = response.data.csrfToken

  if (!csrfToken) {
    throw new Error('CSRF token missing from server response')
  }

  // Attach the token to the original write request
  config.headers = config.headers || {}
  config.headers['x-csrf-token'] = csrfToken

  return config
})
