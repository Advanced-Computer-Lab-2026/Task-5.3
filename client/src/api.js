import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Login and registration are intentionally exempt because no authenticated
// session exists yet. Fetch a fresh session-bound token before every other
// write and send it in a header that an HTML form cannot set.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const isMutation = ['post', 'put', 'patch', 'delete'].includes(method)
  const isPreAuth = /\/auth\/(login|register)\/?$/.test(config.url || '')

  if (!isMutation || isPreAuth) return config

  const { data } = await api.get('/csrf-token')
  if (typeof config.headers?.set === 'function') {
    config.headers.set('x-csrf-token', data.csrfToken)
  } else {
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = data.csrfToken
  }
  return config
})
