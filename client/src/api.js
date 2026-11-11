import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true,
});

let csrfToken = null;
let csrfTokenPromise = null;

export const fetchCsrfToken = () => {
  if (!csrfTokenPromise) {
    csrfTokenPromise = api.get('/csrf-token')
      .then((response) => {
        csrfToken = response.data.csrfToken;
        return csrfToken;
      })
      .finally(() => {
        csrfTokenPromise = null;
      });
  }

  return csrfTokenPromise;
};

api.interceptors.request.use(async (config) => {
  const method = config.method?.toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    if (!csrfToken) {
      await fetchCsrfToken();
    }

    config.headers.set('X-CSRF-Token', csrfToken);
  }

  return config;
});

api.interceptors.response.use((response) => {
  const authRoute = response.config.url?.split('?')[0];
  if (['/auth/login', '/auth/register', '/auth/logout'].includes(authRoute)) {
    csrfToken = null;
  }

  return response;
});

export default api;
