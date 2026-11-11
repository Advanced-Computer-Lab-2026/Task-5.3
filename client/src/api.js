import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

api.interceptors.request.use(async (config) => {
  if (!['get', 'head', 'options'].includes((config.method || 'get').toLowerCase())) {
    if (!csrfToken) {
      const { data } = await api.get('/csrf-token')
      csrfToken = data.csrfToken
    }
    config.headers['x-csrf-token'] = csrfToken
  }
  return config
})

// Session changed, so the cached token is bound to the old one
api.interceptors.response.use((response) => {
  if (/\/auth\/(login|register|logout)$/.test(response.config.url || '')) csrfToken = null
  return response
})