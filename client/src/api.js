
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

// Store the CSRF token once it has been fetched.
let csrfToken = null;

// Fetch a CSRF token from the server.
async function getCsrfToken() {
  if (!csrfToken) {
    const response = await api.get('/csrf-token');
    csrfToken = response.data.csrfToken;
  }

  return csrfToken;
}

// Attach the CSRF token to every state-changing request.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  const mutatingMethods = ['post', 'put', 'patch', 'delete'];

  if (mutatingMethods.includes(method)) {
    const token = await getCsrfToken();

    config.headers = config.headers || {};
    config.headers['X-CSRF-Token'] = token;
  }

  return config;
});
