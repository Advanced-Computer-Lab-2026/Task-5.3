
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true,
});

const SAFE_METHODS = ['get', 'head', 'options'];

const CSRF_EXEMPT_ROUTES = [
  '/auth/login',
  '/auth/register',
];

const AUTH_ROUTES = [
  ...CSRF_EXEMPT_ROUTES,
  '/auth/logout',
];

let csrfToken = null;
let pending = null;

const getUrl = (config) => config.url || '';

const isMutating = (config) =>
  !SAFE_METHODS.includes(
    (config.method || 'get').toLowerCase()
  );

const matchesRoute = (config, routes) =>
  routes.some(route => {
    const url = getUrl(config).split('?')[0];
    return url === route || url.endsWith(route);
  });

const isCsrfExempt = (config) =>
  matchesRoute(config, CSRF_EXEMPT_ROUTES);

const isAuthRoute = (config) =>
  matchesRoute(config, AUTH_ROUTES);

export function clearCsrfToken() {
  csrfToken = null;
}

async function getCsrfToken() {
  if (csrfToken) return csrfToken;

  if (!pending) {
    pending = api.get('/csrf-token')
      .then(response => {
        csrfToken = response.data.csrfToken;
        return csrfToken;
      })
      .finally(() => {
        pending = null;
      });
  }

  return pending;
}

// Attach CSRF token to state-changing requests.
api.interceptors.request.use(async config => {
  if (isMutating(config) && !isCsrfExempt(config)) {
    const token = await getCsrfToken();

    if (typeof config.headers.set === 'function') {
      config.headers.set('x-csrf-token', token);
    } else {
      config.headers['x-csrf-token'] = token;
    }
  }

  return config;
});

// Clear cached token after authentication changes.
api.interceptors.response.use(
  response => {
    if (isAuthRoute(response.config)) {
      clearCsrfToken();
    }

    return response;
  },

  async error => {
    const config = error.config;

    const csrfRejected =
      error.response?.status === 403 &&
      /csrf/i.test(error.response?.data?.message || '');

    if (
      csrfRejected &&
      config &&
      isMutating(config) &&
      !config._csrfRetried
    ) {
      config._csrfRetried = true;
      clearCsrfToken();

      return api.request(config);
    }

    return Promise.reject(error);
  }
);
