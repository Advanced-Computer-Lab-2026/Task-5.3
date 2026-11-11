import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken
const csrfExemptUrls = ['/auth/login', '/auth/register', '/csrf-token']

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (['get', 'head', 'options'].includes(method) ||
      csrfExemptUrls.some(path => url.includes(path))) {
    return config
  }

  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }

  config.headers.set('x-csrf-token', csrfToken)
  return config
})

api.interceptors.response.use(response => {
  const url = response.config.url || ''
  if (url.includes('/auth/login') || url.includes('/auth/register') || url.includes('/auth/logout')) {
    csrfToken = undefined
  }
  return response
})
