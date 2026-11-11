
import axios from 'axios'

let csrfToken = null
let csrfTokenPromise = null

export function setCsrfToken(token) {
  csrfToken = token
}

export function clearCsrfToken() {
  csrfToken = null
  csrfTokenPromise = null
}

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

async function getCsrfToken() {
  if (csrfToken) return csrfToken

  // Reuse an existing request if multiple requests need a token.
  if (!csrfTokenPromise) {
    csrfTokenPromise = api.get('/csrf-token')
      .then(res => {
        csrfToken = res.data.csrfToken
        return csrfToken
      })
      .finally(() => {
        csrfTokenPromise = null
      })
  }

  return csrfTokenPromise
}

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''

  const mutatingMethods = ['post', 'put', 'patch', 'delete']

  // Login and registration establish authentication, so they don't
  // need a CSRF token beforehand.
  const isAuthSetupRequest =
    url.includes('/auth/login') ||
    url.includes('/auth/register')

  if (mutatingMethods.includes(method) && !isAuthSetupRequest) {
    const token = await getCsrfToken()
    config.headers['X-CSRF-Token'] = token
  }

  return config
})
