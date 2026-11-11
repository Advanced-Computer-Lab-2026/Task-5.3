
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;
let csrfTokenRequest = null;
let sessionVersion = 0;

export function clearCsrfToken() {
  csrfToken = null;
  csrfTokenRequest = null;
  sessionVersion += 1;
}

export async function fetchCsrfToken() {
  // Share issuance so simultaneous writes cannot overwrite each other's cookie.
  if (!csrfTokenRequest) {
    const version = sessionVersion;
    const pending = api.get('/csrf-token').then((response) => {
      if (version !== sessionVersion) throw new Error('Session changed while fetching CSRF token');
      csrfToken = response.data.csrfToken;
      return csrfToken;
    });
    csrfTokenRequest = pending;
    pending.finally(() => {
      if (csrfTokenRequest === pending) csrfTokenRequest = null;
    }).catch(() => {});
  }
  return csrfTokenRequest;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  const url = (config.url || '').split(/[?#]/)[0];

  const isAuthRequest =
    url === '/auth/login' ||
    url === '/auth/register';

  const mutatingMethods = ['post', 'put', 'patch', 'delete'];

  if (mutatingMethods.includes(method) && !isAuthRequest) {
    if (!csrfToken) {
      await fetchCsrfToken();
    }

    config.headers.set
      ? config.headers.set('x-csrf-token', csrfToken)
      : config.headers['x-csrf-token'] = csrfToken;
  }

  return config;
});
