import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;
let csrfRequest = null;

export function clearCsrfToken() {
  csrfToken = null;
  csrfRequest = null;
}

async function getCsrfToken() {
  if (csrfToken) {
    return csrfToken;
  }

  if (!csrfRequest) {
    csrfRequest = api.get('/csrf-token')
      .then((res) => {
        csrfToken = res.data.csrfToken;
        return csrfToken;
      })
      .finally(() => {
        csrfRequest = null;
      });
  }

  return csrfRequest;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  const writeMethods = ['post', 'put', 'patch', 'delete'];

  if (!writeMethods.includes(method)) {
    return config;
  }

  const url = config.url || '';

  // Login and registration do not require a CSRF token.
  if (
    url.includes('/auth/login') ||
    url.includes('/auth/register')
  ) {
    return config;
  }

  const token = await getCsrfToken();

  if (typeof config.headers.set === 'function') {
    config.headers.set('x-csrf-token', token);
  } else {
    config.headers['x-csrf-token'] = token;
  }

  return config;
});