import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

export function resetCsrfToken() {
  csrfToken = null
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toUpperCase()
  const url = config.url || ''
  // No session exists yet at login/register, so there's nothing to protect
  // and no token could be issued anyway.
  const isAuthBootstrap = url.includes('/auth/login') || url.includes('/auth/register')

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && !isAuthBootstrap) {
    if (!csrfToken) {
      const { data } = await api.get('/csrf-token')
      csrfToken = data.csrfToken
    }
    config.headers['x-csrf-token'] = csrfToken
  }
  return config
})