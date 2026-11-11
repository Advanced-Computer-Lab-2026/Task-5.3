
import axios from 'axios'

let csrfToken = null

export function setCsrfToken(token) {
  csrfToken = token
}

export function clearCsrfToken() {
  csrfToken = null
}

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

api.interceptors.request.use(config => {
  const method = (config.method || 'get').toLowerCase()

  if (['post', 'put', 'patch', 'delete'].includes(method) && csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken
  }

  return config
})
