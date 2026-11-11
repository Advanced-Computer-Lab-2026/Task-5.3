import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const SAFE_METHODS = ['get', 'head', 'options']

// Echo the CSRF token on every state-changing request. The token is bound to the
// current session, so it is fetched fresh (login/logout change the session) and
// sent in a custom header that a cross-site form cannot set.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || (config.url || '').includes('/csrf-token')) return config

  const { data } = await api.get('/csrf-token')
  config.headers.set('x-csrf-token', data.csrfToken)
  return config
})
