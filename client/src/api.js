import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const SAFE_METHODS = ['get', 'head', 'options']
let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const res = await api.get('/csrf-token')
    csrfToken = res.data.csrfToken
  }
  return csrfToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (!SAFE_METHODS.includes(method) && !url.startsWith('/auth')) {
    config.headers['x-csrf-token'] = await getCsrfToken()
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    if (/\/auth\/(login|register|logout)/.test(res.config.url || '')) csrfToken = null
    return res
  },
  async (err) => {
    const cfg = err.config
    if (err.response?.status === 403 && /csrf/i.test(err.response.data?.message || '') && cfg && !cfg._csrfRetried) {
      cfg._csrfRetried = true
      csrfToken = null
      cfg.headers['x-csrf-token'] = await getCsrfToken()
      return api(cfg)
    }
    return Promise.reject(err)
  }
)