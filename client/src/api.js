import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF protection --------------------------------------------------------
// The server rejects any state-changing request that doesn't echo a valid
// anti-CSRF token in the `x-csrf-token` header. We fetch the token from
// GET /csrf-token (only our origin can read that response, thanks to CORS),
// keep it in memory (never localStorage), and attach it to every write.

const MUTATING_METHODS = ['post', 'put', 'patch', 'delete']
// Requests that create or end a session: the token is bound to the session,
// so after these the cached token is stale and must be refetched.
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pending = null

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  // Share one in-flight request between concurrent writes.
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(({ data }) => (csrfToken = data.csrfToken))
      .finally(() => { pending = null })
  }
  return pending
}

function isMutating(config) {
  return MUTATING_METHODS.includes((config.method || 'get').toLowerCase())
}

function changesSession(config) {
  return SESSION_CHANGING.some((path) => (config.url || '').includes(path))
}

api.interceptors.request.use(async (config) => {
  if (isMutating(config)) {
    config.headers.set('x-csrf-token', await getCsrfToken())
  }
  return config
})

api.interceptors.response.use(
  (response) => {
    if (changesSession(response.config)) csrfToken = null
    return response
  },
  async (error) => {
    const { config, response } = error
    // The token went stale (e.g. the session changed in another tab).
    // Get a fresh one and retry the request once.
    if (response?.status === 403 && response.data?.code === 'EBADCSRFTOKEN' && config && !config._csrfRetried) {
      csrfToken = null
      config._csrfRetried = true
      return api(config)
    }
    return Promise.reject(error)
  }
)
