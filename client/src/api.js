import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const safeMethods = new Set(['get', 'head', 'options'])
const preAuthenticationPaths = new Set(['/api/auth/login', '/api/auth/register'])

function requestPath(config) {
  try {
    const rawUrl = (config.url || '').split('?')[0]
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(rawUrl)) {
      return new URL(rawUrl).pathname.replace(/\/+$/, '') || '/'
    }

    const basePath = new URL(config.baseURL).pathname.replace(/\/+$/, '')
    const relativePath = rawUrl.replace(/^\/+/, '').replace(/\/+$/, '')
    return `${basePath}/${relativePath}`.replace(/\/+$/, '') || '/'
  } catch {
    return (config.url || '').split('?')[0].replace(/\/+$/, '') || '/'
  }
}

// Login and registration happen before an authenticated session exists. All
// other writes first obtain a session-bound token, then echo it in a header.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const path = requestPath(config)

  if (safeMethods.has(method) || (method === 'post' && preAuthenticationPaths.has(path))) {
    return config
  }

  const { data } = await api.get('/csrf-token')
  if (!data?.csrfToken) {
    throw new Error('The server did not return a CSRF token')
  }

  if (typeof config.headers?.set === 'function') {
    config.headers.set('x-csrf-token', data.csrfToken)
  } else {
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = data.csrfToken
  }

  return config
})
