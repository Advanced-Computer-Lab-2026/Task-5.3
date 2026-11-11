import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;

// The interceptor runs automatically before any request leaves the client
api.interceptors.request.use(async (config) => {
  const method = config.method?.toLowerCase();
  
  // Only state-changing requests need the CSRF token
  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    if (!csrfToken) {
      // Fetch the token if we don't have it yet (GET requests skip this block)
      const res = await api.get('/csrf-token');
      csrfToken = res.data.csrfToken;
    }
    // Attach the token to the outgoing request headers
    config.headers['x-csrf-token'] = csrfToken;
  }
  return config;
});