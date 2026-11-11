
import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const isSafeMethod = ['get', 'head', 'options'].includes(method)
  const isCsrfRequest = (config.url || '').includes('/csrf-token')

  if (!isSafeMethod && !isCsrfRequest) {
    if (!csrfToken) {
      const response = await api.get('/csrf-token')
      csrfToken = response.data.csrfToken
    }

    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = csrfToken
  }

  return config
})
