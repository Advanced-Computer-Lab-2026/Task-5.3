import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null
export function resetCsrfToken() { csrfToken = null }

const PRE_AUTH = ['/auth/login', '/auth/register']
const SAFE = ['get', 'head', 'options']

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE.includes(method) || PRE_AUTH.includes(config.url)) return config

  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  config.headers['x-csrf-token'] = csrfToken
  return config
})

// If the token went stale (e.g. session changed), refetch once and retry
api.interceptors.response.use(undefined, async (error) => {
  const { config, response } = error
  if (response?.status === 403 && config && !config._csrfRetried) {
    config._csrfRetried = true
    csrfToken = null
    return api(config)
  }
  return Promise.reject(error)
})