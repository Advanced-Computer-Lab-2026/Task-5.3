import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const SAFE_METHODS = ['get', 'head', 'options']

// Anti-CSRF: before every state-changing request, fetch a token from the API and
// echo it in the x-csrf-token header. Only our own origin can read this token
// (CORS), so a forged cross-site request can never include it.
//
// A fresh token is fetched each time because the token is bound to the session,
// and the session changes on login, register and logout.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method)) return config

  const { data } = await api.get('/csrf-token')
  config.headers = config.headers || {}
  if (typeof config.headers.set === 'function') {
    config.headers.set('x-csrf-token', data.csrfToken)
  } else {
    config.headers['x-csrf-token'] = data.csrfToken
  }
  return config
})
