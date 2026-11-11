import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ── CSRF token handling ──
// The server uses the signed double-submit-cookie pattern (csrf-csrf). The
// browser automatically sends the token *cookie*, but the server also requires
// the token *value* in the x-csrf-token header. A cross-site attacker can
// trigger the cookie but cannot read the token value or set a custom header,
// so echoing the header is what defeats CSRF.
let csrfToken = null

async function fetchCsrfToken() {
  // GET /csrf-token is safe, so the request interceptor below will not
  // recursively try to add a header to it.
  const { data } = await api.get('/csrf-token')
  csrfToken = data.csrfToken
  return csrfToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const isSafe = method === 'get' || method === 'head' || method === 'options'
  const isTokenEndpoint = (config.url || '').includes('/csrf-token')

  // Leave safe methods and the token fetch itself untouched.
  if (isSafe || isTokenEndpoint) return config

  // First mutating request fetches and caches the token; later ones reuse it.
  const token = csrfToken || (await fetchCsrfToken())

  // axios v1 stores headers as an AxiosHeaders instance; fall back to a plain
  // object just in case an older axios (or a test stub) hands us one.
  if (config.headers && typeof config.headers.set === 'function') {
    config.headers.set('x-csrf-token', token)
  } else {
    config.headers = { ...(config.headers || {}), 'x-csrf-token': token }
  }

  return config
})