import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfTokenPromise = null

async function getCsrfToken() {
  if (!csrfTokenPromise) {
    csrfTokenPromise = api.get('/csrf-token')
      .then(res => res.data.csrfToken)
      .catch(err => {
        csrfTokenPromise = null
        throw err
      })
  }
  return csrfTokenPromise
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toUpperCase()
  const mutatingMethods = ['POST', 'PUT', 'PATCH', 'DELETE']
  
  if (mutatingMethods.includes(method) && !config.url?.includes('/csrf-token')) {
    try {
      const token = await getCsrfToken()
      if (token) {
        config.headers['x-csrf-token'] = token
      }
    } catch {
      // If fetching csrf token fails, proceed and let server respond with appropriate status
    }
  }
  return config
})
