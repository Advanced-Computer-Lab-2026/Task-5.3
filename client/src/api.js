import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

async function getCsrfToken() {
  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  return csrfToken
}

const SAFE = ['get', 'head', 'options']
const PRE_AUTH = ['/auth/login', '/auth/register']

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE.includes(method) || PRE_AUTH.includes(config.url)) return config
  config.headers['x-csrf-token'] = await getCsrfToken()
  return config
})

api.interceptors.response.use((res) => {
  if (['/auth/login', '/auth/register', '/auth/logout'].includes(res.config.url)) {
    csrfToken = null
  }
  return res
})