import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Methods that change server state must carry an anti-CSRF token. We fetch a
// fresh one from the server (which also sets the matching csrf cookie) and echo
// it in the `x-csrf-token` header. The attacker's forged request cannot do this:
// it can neither read the token (same-origin policy) nor set this header.
const MUTATING_METHODS = ['post', 'put', 'patch', 'delete']

async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token')
  return data.csrfToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (MUTATING_METHODS.includes(method)) {
    const token = await fetchCsrfToken()
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = token
  }
  return config
})
