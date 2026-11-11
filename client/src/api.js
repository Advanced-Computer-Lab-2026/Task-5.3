import axios from 'axios'

const apiUrl = new URL('http://localhost:4000/api')

export const api = axios.create({
  baseURL: apiUrl.href,
  withCredentials: true
})

const safeMethods = new Set(['get', 'head', 'options'])
let pendingCsrfToken

api.interceptors.request.use(async (config) => {
  if (safeMethods.has(config.method)) return config

  const url = new URL(api.getUri(config))
  if (url.origin !== apiUrl.origin) return config
  if (config.method === 'post' && /^\/api\/auth\/(?:login|register)\/?$/i.test(url.pathname)) {
    return config
  }

  // Share an in-flight fetch so parallel writes use the same newly issued cookie.
  pendingCsrfToken ??= api.get('/csrf-token')
    .then(({ data }) => data.csrfToken)
    .finally(() => { pendingCsrfToken = undefined })

  config.headers.set('x-csrf-token', await pendingCsrfToken)
  return config
})
