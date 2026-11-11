import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken
let csrfTokenRequest

function getPath(config) {
  return (config.url || '').split('?')[0]
}

function isPreAuthRequest(config) {
  const path = getPath(config)
  return path === '/auth/login' || path === '/auth/register'
}

async function getCsrfToken() {
  if (!csrfTokenRequest) {
    csrfTokenRequest = api.get('/csrf-token')
      .then(({ data }) => {
        csrfToken = data.csrfToken
        return csrfToken
      })
      .finally(() => {
        csrfTokenRequest = undefined
      })
  }
  return csrfTokenRequest
}

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  if (['get', 'head', 'options'].includes(method) || isPreAuthRequest(config)) {
    return config
  }

  const token = csrfToken || await getCsrfToken()
  if (typeof config.headers?.set === 'function') {
    config.headers.set('x-csrf-token', token)
  } else {
    config.headers = { ...config.headers, 'x-csrf-token': token }
  }
  return config
})

api.interceptors.response.use(response => {
  const path = getPath(response.config || {})
  if (path === '/csrf-token') {
    csrfToken = response.data.csrfToken
  } else if (isPreAuthRequest(response.config || {}) || path === '/auth/logout') {
    csrfToken = undefined
  }
  return response
})
