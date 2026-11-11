import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let pendingToken

api.interceptors.request.use(async (config) => {
  const method = config.method.toLowerCase()
  if (['get', 'head', 'options'].includes(method)) return config
  if (method === 'post' && ['/auth/login', '/auth/register'].includes(config.url)) return config

  // Concurrent writes share the token request that sets the double-submit cookie.
  pendingToken ??= api.get('/csrf-token').finally(() => { pendingToken = undefined })
  const { data } = await pendingToken
  config.headers.set('x-csrf-token', data.csrfToken)
  return config
})
