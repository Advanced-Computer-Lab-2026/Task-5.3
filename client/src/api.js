import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

export const resetCsrfToken = () => { csrfToken = null }

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const safe = ['get', 'head', 'options'].includes(method)
  const preAuth = ['/auth/login', '/auth/register'].includes(config.url)
  if (!safe && !preAuth) {
    if (!csrfToken) {
      const { data } = await api.get('/csrf-token')
      csrfToken = data.csrfToken
    }
    config.headers['X-CSRF-Token'] = csrfToken
  }
  return config
})