import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const MUTATING_METHODS = new Set(['post', 'put', 'patch', 'delete'])
const PRE_AUTH_ROUTES = new Set(['/auth/login', '/auth/register'])

let csrfToken = null
let csrfTokenRequest = null

function requestPath(config) {
  try {
    return new URL(config.url || '', config.baseURL || api.defaults.baseURL).pathname.replace(/^\/api/, '')
  } catch {
    return config.url || ''
  }
}

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!csrfTokenRequest) {
    csrfTokenRequest = api.get('/csrf-token')
      .then(({ data }) => {
        csrfToken = data.csrfToken
        return csrfToken
      })
      .finally(() => { csrfTokenRequest = null })
  }
  return csrfTokenRequest
}

export function clearCsrfToken() {
  csrfToken = null
  csrfTokenRequest = null
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const path = requestPath(config)

  if (MUTATING_METHODS.has(method) && !PRE_AUTH_ROUTES.has(path) && path !== '/csrf-token') {
    const token = await getCsrfToken()
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = token
  }

  return config
})

api.interceptors.response.use(
  (response) => {
    const path = requestPath(response.config)
    if (PRE_AUTH_ROUTES.has(path) || path === '/auth/logout') clearCsrfToken()
    return response
  },
  (error) => {
    const path = requestPath(error.config || {})
    if (PRE_AUTH_ROUTES.has(path) || path === '/auth/logout' || error.response?.status === 401) {
      clearCsrfToken()
    }
    return Promise.reject(error)
  }
)
