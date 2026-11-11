
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;

export function clearCsrfToken() {
  csrfToken = null;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  const safeMethods = ['get', 'head', 'options'];

  // Safe requests do not require a CSRF token.
  if (safeMethods.includes(method)) {
    return config;
  }

  // Login and registration do not have sessions yet.
  if (
    config.url === '/auth/login' ||
    config.url === '/auth/register'
  ) {
    return config;
  }

  // Retrieve a CSRF token when necessary.
  if (!csrfToken) {
    const response = await api.get('/csrf-token');
    csrfToken = response.data.csrfToken;
  }

  config.headers = config.headers || {};

  config.headers['x-csrf-token'] = csrfToken;

  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (
      error.response?.status === 401 ||
      error.response?.status === 403
    ) {
      clearCsrfToken();
    }

    return Promise.reject(error);
  }
);
