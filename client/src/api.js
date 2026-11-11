import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  const isWrite = !['get', 'head', 'options'].includes(method)
  const isPreAuth = /\/auth\/(login|register)\/?$/.test(config.url || '')

  if (isWrite && !isPreAuth) {
    // Fetch a token tied to the current login cookie, then echo it on this write.
    const { data } = await api.get('/csrf-token')
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = data.csrfToken
  }

  return config
})
