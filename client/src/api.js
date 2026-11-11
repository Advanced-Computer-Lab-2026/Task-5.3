import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS'])
let csrfToken
let csrfTokenRequest

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toUpperCase()
  const url = config.url || ''

  if (
    safeMethods.has(method) ||
    /\/auth\/(?:login|register)$/.test(url)
  ) {
    return config
  }

  if (!csrfToken) {
    csrfTokenRequest ||= api.get('/csrf-token')
      .then(({ data }) => {
        if (typeof data.csrfToken !== 'string' || !data.csrfToken) {
          throw new Error('The server did not return a CSRF token')
        }
        csrfToken = data.csrfToken
        return csrfToken
      })
      .finally(() => { csrfTokenRequest = undefined })
    csrfToken = await csrfTokenRequest
  }

  if (typeof config.headers?.set === 'function') {
    config.headers.set('x-csrf-token', csrfToken)
  } else {
    config.headers = { ...config.headers, 'x-csrf-token': csrfToken }
  }

  return config
})

api.interceptors.response.use(response => {
  if (/\/auth\/(?:login|register|logout)$/.test(response.config.url || '')) {
    csrfToken = undefined
  }
  return response
})
