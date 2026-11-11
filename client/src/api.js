import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null;

export const fetchCsrfToken = async () => {
  try {
    const response = await axios.get('http://localhost:4000/api/csrf-token', { withCredentials: true });
    csrfToken = response.data.csrfToken;
  } catch (error) {
    console.error('Failed to fetch CSRF token', error);
  }
};

api.interceptors.request.use(async (config) => {
  const unsafeMethods = ['post', 'put', 'patch', 'delete'];
  
  if (unsafeMethods.includes(config.method.toLowerCase())) {
    if (!csrfToken) {
      await fetchCsrfToken();
    }
    if (csrfToken) {
      config.headers['x-csrf-token'] = csrfToken;
    }
  }
  return config;
});