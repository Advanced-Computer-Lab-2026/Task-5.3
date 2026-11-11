import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    const response = await api.get('/csrf-token');

    config.headers = config.headers || {};
    config.headers['x-csrf-token'] = response.data.csrfToken;
  }

  return config;
});