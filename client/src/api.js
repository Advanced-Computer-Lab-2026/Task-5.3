import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

const SAFE_METHODS = ['get', 'head', 'options']

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()

  if (SAFE_METHODS.includes(method)) return config

  if (!csrfToken) {
    const res = await api.get('/csrf-token')
    csrfToken = res.data.csrfToken
  }

  config.headers['x-csrf-token'] = csrfToken
  return config
})

export function clearCsrfToken() {
  csrfToken = null
}