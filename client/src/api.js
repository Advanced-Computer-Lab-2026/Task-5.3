
import axios from 'axios'

// Create Axios instance
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Store the CSRF token in memory
let csrfToken = null
let csrfTokenPromise = null

// Fetch a CSRF token from the server
async function getCsrfToken() {
  if (csrfToken) {
    return csrfToken
  }

  if (!csrfTokenPromise) {
    csrfTokenPromise = api.get('/csrf-token')
      .then((response) => {
        csrfToken = response.data.csrfToken
        return csrfToken
      })
      .finally(() => {
        csrfTokenPromise = null
      })
  }

  return csrfTokenPromise
}

// Add CSRF token to state-changing requests
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()

  // Safe requests do not need CSRF protection
  if (['get', 'head', 'options'].includes(method)) {
    return config
  }

  // Login and registration happen before authentication
  if (
    config.url?.includes('/auth/login') ||
    config.url?.includes('/auth/register')
  ) {
    return config
  }

  // Fetch the CSRF token
  const token = await getCsrfToken()

  // Attach it to the request header
  config.headers.set('x-csrf-token', token)

  return config
})

// Clear the cached token when authentication changes
export function clearCsrfToken() {
  csrfToken = null
  csrfTokenPromise = null
}
