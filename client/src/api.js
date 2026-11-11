import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

api.interceptors.request.use(async (config) => {
  // Prevent infinite loop: do not intercept the token fetch itself
  if ((config.url || '').includes('/csrf-token')) {
    return config;
  }

  const method = config.method?.toLowerCase();
  
  // Only intercept state-changing requests
  if (['post', 'patch', 'put', 'delete'].includes(method)) {
    try {
      // Use the `api` instance so the test mock catches it
      const { data } = await api.get('/csrf-token');
      config.headers['x-csrf-token'] = data.csrfToken;
    } catch (error) {
      console.error('Failed to fetch CSRF token:', error);
    }
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});