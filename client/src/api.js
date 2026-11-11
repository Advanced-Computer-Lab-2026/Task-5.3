import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null
const SAFE_METHODS = ['get', 'head', 'options']
const isAuthFlow = (url = '') => /^\/auth\/(login|register|logout)/.test(url)

async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
}

// Attach the token to every state-changing request (lazy-fetched, cached)
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method) && !isAuthFlow(config.url)) {
    if (!csrfToken) await fetchCsrfToken()
    config.headers['X-CSRF-Token'] = csrfToken
  }
  return config
})

// The token is bound to the session cookie, so drop it whenever the session changes
api.interceptors.response.use((res) => {
  if (isAuthFlow(res.config?.url)) csrfToken = null
  return res
})