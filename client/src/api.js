
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

// Request interceptor: attach CSRF token to every mutating request.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  // GET, HEAD and OPTIONS do not need CSRF tokens.
  const mutatingMethods = ['post', 'put', 'patch', 'delete'];

  if (!mutatingMethods.includes(method)) {
    return config;
  }

  // Avoid requesting a CSRF token while already requesting one.
  if ((config.url || '').includes('/csrf-token')) {
    return config;
  }

  // Ask the backend for a CSRF token.
  const response = await api.get('/settings/csrf-token');

  const csrfToken = response.data.csrfToken;

  // Attach it to the outgoing request.
  if (typeof config.headers.set === 'function') {
    config.headers.set('X-CSRF-Token', csrfToken);
  } else {
    config.headers['X-CSRF-Token'] = csrfToken;
  }

  return config;
});
