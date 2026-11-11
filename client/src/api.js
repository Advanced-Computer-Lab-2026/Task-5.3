import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let pendingTokenRequest;

function fetchCsrfToken() {
  if (!pendingTokenRequest) {
    pendingTokenRequest = api.get('/csrf-token')
      .then((response) => response.data.csrfToken)
      .finally(() => {
        pendingTokenRequest = null;
      });
  }

  return pendingTokenRequest;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  const isSafeMethod = ['get', 'head', 'options'].includes(method);

  const isPreAuthRoute =
    method === 'post' &&
    ['/auth/login', '/auth/register'].includes(config.url);

  if (!isSafeMethod && !isPreAuthRoute) {
    const csrfToken = await fetchCsrfToken();
    config.headers['x-csrf-token'] = csrfToken;
  }

  return config;
});