import axios from 'axios'

// `withCredentials: true` sends both the auth cookie and the HttpOnly CSRF
// cookie. The readable token is fetched from the API and echoed in a header;
// login and registration are exempt because no authenticated session exists.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!['post', 'put', 'patch', 'delete'].includes(method)) return config

  const url = config.url || ''
  if (/\/auth\/(login|register)\/?$/.test(url)) return config

  const { data } = await api.get('/csrf-token')
  config.headers.set
    ? config.headers.set('x-csrf-token', data.csrfToken)
    : (config.headers['x-csrf-token'] = data.csrfToken)
  return config
})
