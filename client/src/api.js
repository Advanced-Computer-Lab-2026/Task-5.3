
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;

// Clear the token when the authenticated session changes
export function clearCsrfToken() {
  csrfToken = null;
}

const safeMethods = ['get', 'head', 'options'];

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  const url = config.url || '';

  const isPreAuthRequest =
    url.includes('/auth/login') ||
    url.includes('/auth/register');

  const isCsrfRequest = url.includes('/csrf-token');

  // Only protect state-changing requests
  if (
    !safeMethods.includes(method) &&
    !isPreAuthRequest &&
    !isCsrfRequest
  ) {
    // Obtain a CSRF token if we don't already have one
    if (!csrfToken) {
      const response = await api.get('/csrf-token');
      csrfToken = response.data.csrfToken;
    }

    // Attach the token to the request header
    if (typeof config.headers?.set === 'function') {
      config.headers.set('x-csrf-token', csrfToken);
    } else {
      config.headers = config.headers || {};
      config.headers['x-csrf-token'] = csrfToken;
    }
  }

  return config;
});
