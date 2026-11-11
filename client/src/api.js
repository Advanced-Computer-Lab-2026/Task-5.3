import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;

// Export function to reset token on session changes (we will use this in Step 5!)
export function resetCsrf() {
  csrfToken = null;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  // GET, HEAD, and OPTIONS requests only read data, so skip CSRF header
  if (['get', 'head', 'options'].includes(method)) return config;

  // Skip login and register calls since the user doesn't have a session yet
  const url = config.url || '';
  if (url.includes('/auth/login') || url.includes('/auth/register')) return config;

  // Fetch a token from the server if we haven't cached one yet
  if (!csrfToken) {
    const { data } = await api.get('/csrf-token');
    csrfToken = data.csrfToken;
  }

  // Attach Token 2 to the request header
  config.headers['x-csrf-token'] = csrfToken;
  return config;
});