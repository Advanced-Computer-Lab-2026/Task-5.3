import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Attach an anti-CSRF token to every state-changing request. The token comes from
// the API's GET /csrf-token endpoint (which also sets a matching cookie). Because
// an attacker's page cannot read this token, it cannot forge a valid mutating
// request — this header is what defeats CSRF. Safe GET requests need no token.
const MUTATING = ['post', 'put', 'patch', 'delete']

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (MUTATING.includes(method)) {
    const { data } = await api.get('/csrf-token')
    if (config.headers && typeof config.headers.set === 'function') {
      config.headers.set('x-csrf-token', data.csrfToken)
    } else {
      config.headers = { ...(config.headers || {}), 'x-csrf-token': data.csrfToken }
    }
  }
  return config
})