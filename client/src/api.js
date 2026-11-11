import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true,
});

let pendingToken;

// Share concurrent token requests, and propagate failures instead of sending an
// unprotected write. Fetch again for later writes so session changes are honored.
export const setupCsrf = () => {
  if (!pendingToken) {
    pendingToken = api.get('/csrf-token')
      .then(({ data }) => {
        if (!data.csrfToken) throw new Error('Missing CSRF token');
        return data.csrfToken;
      })
      .finally(() => { pendingToken = undefined; });
  }
  return pendingToken;
};

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  const exempt = ['/auth/login', '/auth/register'].includes(config.url);
  if (!['get', 'head', 'options'].includes(method) && !exempt) {
    config.headers['x-csrf-token'] = await setupCsrf();
  }
  return config;
});
