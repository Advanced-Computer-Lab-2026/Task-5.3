import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth and CSRF
// cookies on cross-origin requests to the API.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const MUTATING_METHODS = new Set(['post', 'put', 'patch', 'delete'])
const CSRF_EXEMPT_PATHS = ['/auth/login', '/auth/register']

let inFlightCsrfRequest = null

async function fetchCsrfToken() {
  if (!inFlightCsrfRequest) {
    inFlightCsrfRequest = api
      .get('/csrf-token')
      .then((res) => res.data.csrfToken)
      .finally(() => {
        inFlightCsrfRequest = null
      })
  }
  return inFlightCsrfRequest
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const path = (config.url || '').split('?')[0].replace(/\/+$/, '')
  const isExempt = CSRF_EXEMPT_PATHS.some((exempt) => path === exempt || path.endsWith(exempt))

  if (MUTATING_METHODS.has(method) && !path.endsWith('/csrf-token') && !isExempt) {
    const token = await fetchCsrfToken()
    config.headers = config.headers || {}
    if (typeof config.headers.set === 'function') {
      config.headers.set('x-csrf-token', token)
    } else {
      config.headers['x-csrf-token'] = token
    }
  }

  return config
})
