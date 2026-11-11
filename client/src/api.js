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
  if (['get', 'head', 'options'].includes(method)) return config

  const url = config.url || ''
  if (/\/auth\/(login|register)(?:\?|$)/.test(url)) return config

  const { data } = await api.get('/csrf-token')
  if (typeof config.headers.set === 'function') {
    config.headers.set('x-csrf-token', data.csrfToken)
  } else {
    config.headers['x-csrf-token'] = data.csrfToken
  }
  return config
})
