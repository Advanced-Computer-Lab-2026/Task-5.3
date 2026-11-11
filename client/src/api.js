import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;

api.interceptors.request.use(async (config) => {
  const method = config.method?.toLowerCase();

  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    if (!['/auth/login', '/auth/register'].includes(config.url)) {
      if (!csrfToken) {
        const response = await api.get('/csrf-token');
        csrfToken = response.data.csrfToken;
      }

      config.headers['x-csrf-token'] = csrfToken;
    }
  }

  return config;
});