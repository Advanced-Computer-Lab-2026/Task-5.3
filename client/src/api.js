import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

export function setCsrfToken(token) {
  csrfToken = token
}

api.interceptors.request.use(async config => {
  const method = config.method?.toLowerCase()
  const isMutation = !['get', 'head', 'options'].includes(method)
  const isPreAuth = ['/auth/login', '/auth/register'].includes(config.url)

  if (isMutation && !isPreAuth && !csrfToken) {
    try {
      const response = await api.get('/csrf-token')
      setCsrfToken(response.data.csrfToken)
    } catch (error) {
      return Promise.reject(error)
    }
  }
  if (isMutation && !isPreAuth && csrfToken) {
    config.headers['x-csrf-token'] = csrfToken
  }
  return config
})
