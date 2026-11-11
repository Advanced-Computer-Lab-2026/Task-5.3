import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// CSRF: every state-changing request echoes the server-issued token in a header.
let csrfToken = null
const SAFE = ['get', 'head', 'options']

async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

api.interceptors.request.use(async (config) => {
  if (!SAFE.includes((config.method || 'get').toLowerCase())) {
    config.headers['x-csrf-token'] = csrfToken || (await fetchCsrfToken())
  }
  return config
})

// The token is tied to the session, so it goes stale after login/logout.
// On a 403, fetch a fresh token and retry once.
api.interceptors.response.use(undefined, async (error) => {
  const cfg = error.config
  if (error.response?.status === 403 && cfg && !cfg._csrfRetried) {
    cfg._csrfRetried = true
    cfg.headers['x-csrf-token'] = await fetchCsrfToken()
    return api(cfg)
  }
  return Promise.reject(error)
})
