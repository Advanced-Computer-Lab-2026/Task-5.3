
import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null
let csrfTokenRequest = null

const safeMethods = ['get', 'head', 'options']

function isLoginOrRegister(url = '') {
  return /\/auth\/(login|register)\/?$/.test(url)
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()

  // Safe requests don't need a CSRF token.
  if (safeMethods.includes(method)) {
    return config
  }

  // Login and registration happen before an authenticated session exists.
  if (isLoginOrRegister(config.url)) {
    return config
  }

  // Obtain a token if we don't already have one.
  if (!csrfToken) {
    if (!csrfTokenRequest) {
      csrfTokenRequest = api.get('/csrf-token')
        .then(({ data }) => {
          csrfToken = data.csrfToken
          return csrfToken
        })
        .finally(() => {
          csrfTokenRequest = null
        })
    }

    await csrfTokenRequest
  }

  config.headers = config.headers || {}
  config.headers['X-CSRF-Token'] = csrfToken

  return config
})

// A successful login, registration or logout changes the session.
// The next write request will fetch a fresh token.
api.interceptors.response.use((response) => {
  const url = response.config?.url || ''

  if (/\/auth\/(login|register|logout)\/?$/.test(url)) {
    csrfToken = null
  }

  return response
})
