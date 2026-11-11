
import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

let csrfToken = null;
let csrfTokenPromise = null;

async function getCsrfToken() {
  if (csrfToken) return csrfToken;

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
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();

  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    const token = await getCsrfToken();

    config.headers = config.headers || {};
    config.headers['x-csrf-token'] = token;
  }

  return config;
});
