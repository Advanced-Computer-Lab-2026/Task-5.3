import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken
let tokenRequest

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  const isWrite = !['get', 'head', 'options'].includes(method)
  const isPreAuthentication = /\/auth\/(login|register)(\?|$)/.test(url)

  if (isWrite && !isPreAuthentication) {
    if (!csrfToken) {
      tokenRequest ||= api.get('/csrf-token').then(({ data }) => {
        csrfToken = data.csrfToken
        return csrfToken
      }).finally(() => { tokenRequest = null })
      await tokenRequest
    }
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = csrfToken
  }

  return config
})

api.interceptors.response.use(response => {
  if (/\/auth\/(login|register|logout)(\?|$)/.test(response.config.url || '')) {
    csrfToken = undefined
    tokenRequest = null
  }
  return response
})
